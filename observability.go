package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type taskIdentity struct {
	TaskID, AvailabilityZone string
}

type jsonLogger struct {
	mu            sync.Mutex
	out           io.Writer
	service, mode string
	identity      taskIdentity
	metrics       *requestMetrics
}

var appLogger = newJSONLogger(os.Stdout, "shorturl", "startup", taskIdentity{TaskID: "local"})

func newJSONLogger(out io.Writer, service, mode string, identity taskIdentity) *jsonLogger {
	return &jsonLogger{
		out: out, service: service, mode: mode, identity: identity,
		metrics: newRequestMetrics(service, identity),
	}
}

type requestMetrics struct {
	registry *prometheus.Registry
	requests *prometheus.CounterVec
	duration *prometheus.HistogramVec
}

func newRequestMetrics(service string, identity taskIdentity) *requestMetrics {
	labels := prometheus.Labels{
		"service": service, "task_id": identity.TaskID, "availability_zone": identity.AvailabilityZone,
	}
	metricLabels := []string{"route", "method", "status", "request_kind"}
	metrics := &requestMetrics{
		registry: prometheus.NewRegistry(),
		requests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "shorturl_http_requests_total", Help: "Completed HTTP requests handled by this task.", ConstLabels: labels,
		}, metricLabels),
		duration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name: "shorturl_http_request_duration_seconds", Help: "HTTP handler duration in seconds.", ConstLabels: labels,
			Buckets: []float64{0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10},
		}, metricLabels),
	}
	info := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "shorturl_task_info", Help: "Task identity; always 1 while the metrics endpoint is available.", ConstLabels: labels,
	})
	info.Set(1)
	metrics.registry.MustRegister(metrics.requests, metrics.duration, info)
	if endpoint := strings.TrimRight(os.Getenv("ECS_CONTAINER_METADATA_URI_V4"), "/"); endpoint != "" {
		metrics.registry.MustRegister(newContainerResourceCollector(endpoint, labels))
	}
	return metrics
}

// Read resource usage only during a metrics scrape, not on the API request path.
// These are this API container's values; the limits belong to its enclosing task.
type containerResourceCollector struct {
	endpoint                                    string
	client                                      *http.Client
	success, cpu, cpuLimit, memory, memoryLimit *prometheus.Desc
}

func newContainerResourceCollector(endpoint string, labels prometheus.Labels) *containerResourceCollector {
	return &containerResourceCollector{
		endpoint: endpoint,
		client: &http.Client{
			Timeout: time.Second,
			// Task-local metadata must not go through an outbound HTTP proxy.
			Transport:     &http.Transport{MaxIdleConnsPerHost: 2, IdleConnTimeout: 30 * time.Second},
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse },
		},
		success: prometheus.NewDesc("shorturl_container_resource_scrape_success",
			"Whether this scrape obtained valid API container stats and task limits (1 or 0).", nil, labels),
		cpu: prometheus.NewDesc("shorturl_container_cpu_usage_seconds_total",
			"Cumulative CPU time consumed by this API container in seconds.", nil, labels),
		cpuLimit: prometheus.NewDesc("shorturl_task_cpu_limit_cores",
			"CPU allocated to the enclosing ECS task in vCPUs; not the container's CPU shares.", nil, labels),
		memory: prometheus.NewDesc("shorturl_container_memory_usage_bytes",
			"Current API container memory usage in bytes, including cache reported by the runtime.", nil, labels),
		memoryLimit: prometheus.NewDesc("shorturl_task_memory_limit_bytes",
			"Memory allocated to the enclosing ECS task in bytes.", nil, labels),
	}
}

func (collector *containerResourceCollector) Describe(ch chan<- *prometheus.Desc) {
	for _, descriptor := range []*prometheus.Desc{
		collector.success, collector.cpu, collector.cpuLimit, collector.memory, collector.memoryLimit,
	} {
		ch <- descriptor
	}
}

func (collector *containerResourceCollector) Collect(ch chan<- prometheus.Metric) {
	// A metadata outage must not fail the existing HTTP metrics or report fake
	// zero usage. The common deadline bounds both metadata requests together.
	success := float64(0)
	defer func() {
		ch <- prometheus.MustNewConstMetric(collector.success, prometheus.GaugeValue, success)
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	var task struct {
		Limits struct {
			CPU    float64
			Memory float64 // ECS metadata reports this in MiB.
		}
	}
	if err := collector.getJSON(ctx, "/task", &task); err != nil || task.Limits.CPU <= 0 || task.Limits.Memory <= 0 {
		return
	}
	var stats struct {
		CPU struct {
			Usage struct {
				Total *uint64 `json:"total_usage"` // Runtime CPU time is in nanoseconds.
			} `json:"cpu_usage"`
		} `json:"cpu_stats"`
		Memory struct {
			Usage *uint64 `json:"usage"`
		} `json:"memory_stats"`
	}
	if err := collector.getJSON(ctx, "/stats", &stats); err != nil || stats.CPU.Usage.Total == nil || stats.Memory.Usage == nil {
		return
	}
	ch <- prometheus.MustNewConstMetric(collector.cpu, prometheus.CounterValue,
		float64(*stats.CPU.Usage.Total)/float64(time.Second))
	ch <- prometheus.MustNewConstMetric(collector.cpuLimit, prometheus.GaugeValue, task.Limits.CPU)
	ch <- prometheus.MustNewConstMetric(collector.memory, prometheus.GaugeValue, float64(*stats.Memory.Usage))
	ch <- prometheus.MustNewConstMetric(collector.memoryLimit, prometheus.GaugeValue, task.Limits.Memory*1024*1024)
	success = 1
}

func (collector *containerResourceCollector) getJSON(ctx context.Context, path string, result interface{}) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, collector.endpoint+path, nil)
	if err != nil {
		return err
	}
	response, err := collector.client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return errors.New("ECS metadata returned a non-200 status")
	}
	return json.NewDecoder(io.LimitReader(response.Body, 1024*1024)).Decode(result)
}

func (metrics *requestMetrics) observe(c *gin.Context, route string, elapsed time.Duration) {
	method := c.Request.Method
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut, http.MethodPatch,
		http.MethodDelete, http.MethodConnect, http.MethodOptions, http.MethodTrace:
	default:
		method = "OTHER"
	}
	kind := "traffic"
	if route == "/url_api/healthz" {
		userAgent := c.Request.UserAgent()
		host, _, _ := net.SplitHostPort(c.Request.RemoteAddr)
		ip := net.ParseIP(host)
		// Keep the k6 healthz workload separate from ALB and local wget probes.
		localProbe := ip != nil && ip.IsLoopback() && (userAgent == "Wget" || strings.HasPrefix(userAgent, "Wget/"))
		if strings.HasPrefix(userAgent, "ELB-HealthChecker/") || localProbe {
			kind = "probe"
		}
	}
	values := []string{route, method, strconv.Itoa(c.Writer.Status()), kind}
	metrics.requests.WithLabelValues(values...).Inc()
	metrics.duration.WithLabelValues(values...).Observe(elapsed.Seconds())
}

// Opt in with METRICS_ADDR=127.0.0.1:9090 locally. In ECS, bind a dedicated port
// and permit access only from the monitoring security group; do not route it via ALB.
func startMetricsServer(logger *jsonLogger, shutdownTimeout time.Duration) (func(), error) {
	address := strings.TrimSpace(os.Getenv("METRICS_ADDR"))
	if address == "" {
		return func() {}, nil
	}
	handler := promhttp.HandlerFor(logger.metrics.registry, promhttp.HandlerOpts{
		DisableCompression: true, MaxRequestsInFlight: 2, Timeout: 5 * time.Second,
	})
	mux := http.NewServeMux()
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		handler.ServeHTTP(w, r)
	})
	server := &http.Server{
		Addr: address, Handler: mux, ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second,
	}
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return nil, err
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.event("error", "metrics_server_failed", map[string]interface{}{"error": err.Error()})
		}
	}()
	logger.event("info", "metrics_listening", map[string]interface{}{"address": listener.Addr().String()})
	return func() {
		ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()
		if err := server.Shutdown(ctx); err != nil {
			_ = server.Close()
			logger.event("error", "metrics_shutdown_failed", map[string]interface{}{"error": err.Error()})
		}
		<-done
	}, nil
}

func (logger *jsonLogger) event(level, event string, fields map[string]interface{}) {
	record := map[string]interface{}{
		"time": time.Now().UTC().Format(time.RFC3339Nano), "level": level, "event": event,
		"Service": logger.service, "mode": logger.mode, "TaskId": logger.identity.TaskID,
		"availability_zone": logger.identity.AvailabilityZone,
	}
	for key, value := range fields {
		record[key] = value
	}
	logger.mu.Lock()
	defer logger.mu.Unlock()
	_ = json.NewEncoder(logger.out).Encode(record)
}

// Adapt existing standard-library logs to one JSON event per line.
func (logger *jsonLogger) Write(data []byte) (int, error) {
	logger.event("info", "application_log", map[string]interface{}{"message": strings.TrimSpace(string(data))})
	return len(data), nil
}

func loadTaskIdentity(ctx context.Context) taskIdentity {
	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "local"
	}
	identity := taskIdentity{TaskID: hostname}
	endpoint := strings.TrimRight(os.Getenv("ECS_CONTAINER_METADATA_URI_V4"), "/")
	if endpoint == "" {
		return identity
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint+"/task", nil)
	if err != nil {
		return identity
	}
	response, err := (&http.Client{Timeout: time.Second}).Do(request)
	if err != nil {
		return identity
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return identity
	}
	var metadata struct {
		TaskARN, AvailabilityZone string
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, 64*1024)).Decode(&metadata); err != nil || metadata.TaskARN == "" {
		return identity
	}
	identity.TaskID = metadata.TaskARN[strings.LastIndex(metadata.TaskARN, "/")+1:]
	identity.AvailabilityZone = metadata.AvailabilityZone
	return identity
}

func requestID(header string) string {
	if header != "" && len(header) <= 128 {
		valid := true
		for _, char := range header {
			if !((char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') || (char >= '0' && char <= '9') || char == '-' || char == '_' || char == '.') {
				valid = false
				break
			}
		}
		if valid {
			return header
		}
	}
	var bytes [16]byte
	if _, err := rand.Read(bytes[:]); err == nil {
		return hex.EncodeToString(bytes[:])
	}
	return time.Now().UTC().Format("20060102T150405.000000000")
}

func requestLogging(logger *jsonLogger, cfg config) gin.HandlerFunc {
	return func(c *gin.Context) {
		started := time.Now()
		id := requestID(c.GetHeader("X-Request-ID"))
		c.Set("request_id", id)
		c.Header("X-Request-ID", id)
		c.Next()
		route := c.FullPath()
		if route == "" {
			route = "unmatched"
		}
		status := c.Writer.Status()
		elapsed := time.Since(started)
		logger.metrics.observe(c, route, elapsed)
		fields := map[string]interface{}{
			"request_id": id, "Route": route, "Method": c.Request.Method,
			"status": status, "Latency": float64(elapsed.Microseconds()) / 1000,
		}
		level := "info"
		if status >= 500 {
			level = "error"
			fields["error_type"] = "server_error"
		} else if status >= 400 {
			fields["error_type"] = "client_error"
		}
		if cfg.EnableEMF && route != "/url_api/healthz" {
			fields["Requests"] = 1
			fields["Errors"] = 0
			if status >= 500 {
				fields["Errors"] = 1
			}
			fields["_aws"] = map[string]interface{}{
				"Timestamp": time.Now().UnixMilli(),
				"CloudWatchMetrics": []interface{}{map[string]interface{}{
					"Namespace":  cfg.MetricsNamespace,
					"Dimensions": [][]string{{"Service", "Route", "Method"}, {"Service", "TaskId"}},
					"Metrics": []interface{}{
						map[string]string{"Name": "Requests", "Unit": "Count"},
						map[string]string{"Name": "Errors", "Unit": "Count"},
						map[string]string{"Name": "Latency", "Unit": "Milliseconds"},
					},
				}},
			}
		}
		// Route templates keep URL codes, OAuth codes, tokens and query strings out of logs and metric dimensions.
		logger.event(level, "http_request", fields)
	}
}

func recoverRequests(logger *jsonLogger) gin.HandlerFunc {
	return func(c *gin.Context) {
		defer func() {
			if recover() != nil {
				logger.event("error", "request_panicked", map[string]interface{}{"request_id": c.GetString("request_id"), "error_type": "panic"})
				c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
			}
		}()
		c.Next()
	}
}

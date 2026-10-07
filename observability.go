package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

type taskIdentity struct {
	TaskID, AvailabilityZone string
}

type jsonLogger struct {
	mu            sync.Mutex
	out           io.Writer
	service, mode string
	identity      taskIdentity
}

var appLogger = newJSONLogger(os.Stdout, "shorturl", "startup", taskIdentity{TaskID: "local"})

func newJSONLogger(out io.Writer, service, mode string, identity taskIdentity) *jsonLogger {
	return &jsonLogger{out: out, service: service, mode: mode, identity: identity}
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
		fields := map[string]interface{}{
			"request_id": id, "Route": route, "Method": c.Request.Method,
			"status": status, "Latency": float64(time.Since(started).Microseconds()) / 1000,
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

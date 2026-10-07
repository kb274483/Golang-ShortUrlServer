package main

import (
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type tableNames struct {
	ShortURLs, Users, Itineraries, Subscriptions string
}

type config struct {
	Port, AWSRegion, PublicBaseURL, GoogleRedirectURL string
	GoogleClientID, GoogleClientSecret                string
	Tables                                            tableNames
	ShutdownTimeout, WorkerTimeout, HTTPTimeout       time.Duration
	ServiceName, MetricsNamespace                     string
	EnableEMF                                         bool
}

// Loaded once before serving requests; replicas receive the same deployment settings.
var appConfig = defaultConfig()

func defaultConfig() config {
	return config{
		Port: "8080", AWSRegion: "ap-northeast-1",
		PublicBaseURL: "https://brief-url.link", GoogleRedirectURL: "http://localhost:9001",
		Tables:          tableNames{"shorturl_service", "user_data", "daily_itinerary", "subscription"},
		ShutdownTimeout: 20 * time.Second, WorkerTimeout: 5 * time.Minute, HTTPTimeout: 15 * time.Second,
		ServiceName: "shorturl", MetricsNamespace: "ShortURL/API",
	}
}

func loadConfig() (config, error) {
	cfg := defaultConfig()
	settings := map[string]*string{
		"PORT": &cfg.Port, "AWS_REGION": &cfg.AWSRegion,
		"PUBLIC_BASE_URL": &cfg.PublicBaseURL, "GOOGLE_REDIRECT_URL": &cfg.GoogleRedirectURL,
		"SHORTURL_TABLE_NAME": &cfg.Tables.ShortURLs, "USER_TABLE_NAME": &cfg.Tables.Users,
		"ITINERARY_TABLE_NAME": &cfg.Tables.Itineraries, "SUBSCRIPTION_TABLE_NAME": &cfg.Tables.Subscriptions,
		"SERVICE_NAME": &cfg.ServiceName, "METRICS_NAMESPACE": &cfg.MetricsNamespace,
	}
	for name, target := range settings {
		if value := strings.TrimSpace(os.Getenv(name)); value != "" {
			*target = value
		}
	}
	cfg.GoogleClientID = strings.TrimSpace(os.Getenv("GCP_CLIENT_SECRET_ID"))
	cfg.GoogleClientSecret = strings.TrimSpace(os.Getenv("GCP_CLIENT_SECRET_KEY"))
	if (cfg.GoogleClientID == "") != (cfg.GoogleClientSecret == "") {
		return config{}, fmt.Errorf("GCP_CLIENT_SECRET_ID and GCP_CLIENT_SECRET_KEY must be configured together")
	}
	port, err := strconv.Atoi(cfg.Port)
	if err != nil || port < 1 || port > 65535 {
		return config{}, fmt.Errorf("PORT must be between 1 and 65535")
	}
	for name, value := range map[string]string{"PUBLIC_BASE_URL": cfg.PublicBaseURL, "GOOGLE_REDIRECT_URL": cfg.GoogleRedirectURL} {
		u, err := url.Parse(value)
		if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
			return config{}, fmt.Errorf("%s must be an absolute HTTP(S) URL without credentials, query or fragment", name)
		}
		if name == "PUBLIC_BASE_URL" && u.Path != "" && u.Path != "/" {
			return config{}, fmt.Errorf("PUBLIC_BASE_URL must not include a path")
		}
	}
	cfg.PublicBaseURL = strings.TrimRight(cfg.PublicBaseURL, "/")
	tablePattern := regexp.MustCompile(`^[A-Za-z0-9_.-]{3,255}$`)
	for _, name := range []string{cfg.Tables.ShortURLs, cfg.Tables.Users, cfg.Tables.Itineraries, cfg.Tables.Subscriptions} {
		if !tablePattern.MatchString(name) {
			return config{}, fmt.Errorf("DynamoDB table names must contain 3-255 letters, digits, underscores, periods or hyphens")
		}
	}
	for name, target := range map[string]*time.Duration{
		"SHUTDOWN_TIMEOUT": &cfg.ShutdownTimeout, "WORKER_TIMEOUT": &cfg.WorkerTimeout, "HTTP_TIMEOUT": &cfg.HTTPTimeout,
	} {
		if value := strings.TrimSpace(os.Getenv(name)); value != "" {
			duration, err := time.ParseDuration(value)
			if err != nil || duration <= 0 {
				return config{}, fmt.Errorf("%s must be a positive duration, for example 20s", name)
			}
			*target = duration
		}
	}
	if value := strings.TrimSpace(os.Getenv("ENABLE_EMF_METRICS")); value != "" {
		cfg.EnableEMF, err = strconv.ParseBool(value)
		if err != nil {
			return config{}, fmt.Errorf("ENABLE_EMF_METRICS must be true or false")
		}
	}
	if len(cfg.ServiceName) > 255 || len(cfg.MetricsNamespace) > 255 || strings.HasPrefix(cfg.MetricsNamespace, "AWS/") || strings.ContainsAny(cfg.ServiceName+cfg.MetricsNamespace, "\r\n\t") {
		return config{}, fmt.Errorf("invalid SERVICE_NAME or METRICS_NAMESPACE (custom namespaces must not start with AWS/)")
	}
	return cfg, nil
}

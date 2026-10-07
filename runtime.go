package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

func parseMode(args []string) (string, error) {
	if len(args) == 0 {
		return "api", nil
	}
	if len(args) == 1 && (args[0] == "api" || args[0] == "worker") {
		return args[0], nil
	}
	return "", errors.New("usage: shorturl [api|worker]")
}

func newAWSSession(cfg config) (*session.Session, error) {
	// Do not override Credentials: the SDK supports local credentials, ECS task
	// roles and EC2 instance roles, including temporary credential refresh.
	return session.NewSessionWithOptions(session.Options{
		SharedConfigState: session.SharedConfigEnable,
		Config: aws.Config{
			Region:     aws.String(cfg.AWSRegion),
			HTTPClient: &http.Client{Timeout: cfg.HTTPTimeout},
		},
	})
}

func run(ctx context.Context, args []string) error {
	mode, err := parseMode(args)
	if err != nil {
		return err
	}
	if err := godotenv.Load(); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("load .env: %w", err)
	}
	cfg, err := loadConfig()
	if err != nil {
		return fmt.Errorf("load configuration: %w", err)
	}
	secrets, err := loadRuntimeSecrets()
	if err != nil {
		return fmt.Errorf("load runtime secrets: %w", err)
	}
	appConfig = cfg
	JWTKey, vapidPublicKey, vapidPrivateKey = secrets.jwtKey, secrets.vapidPublicKey, secrets.vapidPrivateKey
	identity := loadTaskIdentity(ctx)
	appLogger = newJSONLogger(os.Stdout, cfg.ServiceName, mode, identity)
	log.SetFlags(0)
	log.SetOutput(appLogger)
	gin.SetMode(gin.ReleaseMode)
	sess, err := newAWSSession(cfg)
	if err != nil {
		return fmt.Errorf("initialize AWS session: %w", err)
	}
	svc := dynamodb.New(sess)
	appLogger.event("info", "application_started", map[string]interface{}{"mode": mode})
	if mode == "worker" {
		workerCtx, cancel := context.WithTimeout(ctx, cfg.WorkerTimeout)
		defer cancel()
		store := contextReminderStore{ctx: workerCtx, svc: svc}
		send := func(subscription sendSub, payload []byte) error {
			return sendNotificationWithContext(workerCtx, subscription, payload)
		}
		if err := runReminderWorker(workerCtx, store, cfg.Tables, time.Now(), send); err != nil {
			return fmt.Errorf("notification worker: %w", err)
		}
		appLogger.event("info", "worker_completed", nil)
		return nil
	}
	googleOauthConfig = &oauth2.Config{
		ClientID: cfg.GoogleClientID, ClientSecret: cfg.GoogleClientSecret,
		RedirectURL: cfg.GoogleRedirectURL,
		Scopes:      []string{"https://www.googleapis.com/auth/userinfo.email"}, Endpoint: google.Endpoint,
	}
	server := newHTTPServer(cfg, newRouter(svc))
	listener, err := net.Listen("tcp", server.Addr)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	appLogger.event("info", "api_listening", map[string]interface{}{"address": server.Addr})
	return serveHTTP(ctx, server, listener, cfg.ShutdownTimeout)
}

func newHTTPServer(cfg config, handler http.Handler) *http.Server {
	return &http.Server{
		Addr: ":" + cfg.Port, Handler: handler,
		ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second,
		WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second,
		ErrorLog: log.New(appLogger, "", 0),
	}
}

func serveHTTP(ctx context.Context, server *http.Server, listener net.Listener, timeout time.Duration) error {
	result := make(chan error, 1)
	go func() { result <- server.Serve(listener) }()
	select {
	case err := <-result:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		appLogger.event("info", "shutdown_started", nil)
		shutdownCtx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			_ = server.Close()
			<-result
			return fmt.Errorf("graceful shutdown: %w", err)
		}
		if err := <-result; err != nil && !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		appLogger.event("info", "shutdown_completed", nil)
		return nil
	}
}

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if err := run(ctx, os.Args[1:]); err != nil {
		appLogger.event("error", "application_failed", map[string]interface{}{"error": err.Error()})
		os.Exit(1)
	}
}

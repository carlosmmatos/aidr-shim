// Package main provides the entry point for the AIDR GCP ext_proc shim.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/reflection"

	"github.com/crowdstrike/aidr-go"
	"github.com/crowdstrike/aidr-go/option"

	"github.com/crowdstrike/aidr-gcp-shim/internal/server"
	"github.com/crowdstrike/aidr-gcp-shim/pkg/config"
)

func main() {
	// Initialize logger
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
	slog.SetDefault(logger)

	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		logger.Error("failed to load configuration", "error", err)
		os.Exit(1)
	}

	// Set log level
	var logLevel slog.Level
	switch cfg.LogLevel {
	case "debug":
		logLevel = slog.LevelDebug
	case "info":
		logLevel = slog.LevelInfo
	case "warn":
		logLevel = slog.LevelWarn
	case "error":
		logLevel = slog.LevelError
	default:
		logLevel = slog.LevelInfo
	}
	logger = slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: logLevel,
	}))
	slog.SetDefault(logger)

	// Log startup mode
	mode := "normal"
	if cfg.EchoMode {
		mode = "echo"
	} else if cfg.DebugMode {
		mode = "debug"
	}
	logger.Info("starting AIDR ext_proc shim",
		"mode", mode,
		"debug_mode", cfg.DebugMode,
		"echo_mode", cfg.EchoMode,
	)

	// Initialize AIDR client
	// The base URL template supports {SERVICE_NAME} placeholder
	aidrClient := aidr.NewClient(
		option.WithBaseURLTemplate(cfg.AIDRCloud),
		option.WithToken(cfg.AIDRToken),
	)

	// Create callout service
	calloutService := server.NewCalloutService(server.CalloutServiceParams{
		AIDRClient:          server.NewAIDRClientWrapper(&aidrClient),
		CollectorInstanceID: cfg.CollectorInstanceID,
		Logger:              logger,
		DebugMode:           cfg.DebugMode,
		EchoMode:            cfg.EchoMode,
	})

	// Create gRPC server
	grpcServer := grpc.NewServer()
	extprocv3.RegisterExternalProcessorServer(grpcServer, calloutService)

	// Register gRPC health service
	healthServer := health.NewServer()
	healthpb.RegisterHealthServer(grpcServer, healthServer)
	healthServer.SetServingStatus("", healthpb.HealthCheckResponse_SERVING)

	// Enable reflection for debugging
	reflection.Register(grpcServer)

	// Create listeners
	grpcListener, err := net.Listen("tcp", fmt.Sprintf(":%d", cfg.GRPCPort))
	if err != nil {
		logger.Error("failed to create gRPC listener", "error", err, "port", cfg.GRPCPort)
		os.Exit(1)
	}

	// Create HTTP health check server
	healthMux := http.NewServeMux()
	healthMux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte("OK")); err != nil {
			logger.Debug("failed to write health response", "error", err)
		}
	})
	healthMux.HandleFunc("/ready", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte("OK")); err != nil {
			logger.Debug("failed to write ready response", "error", err)
		}
	})

	healthHTTPServer := &http.Server{
		Addr:         fmt.Sprintf(":%d", cfg.HealthPort),
		Handler:      healthMux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	// Start servers
	errCh := make(chan error, 2)

	go func() {
		logger.Info("starting gRPC server", "port", cfg.GRPCPort)
		if err := grpcServer.Serve(grpcListener); err != nil {
			errCh <- fmt.Errorf("gRPC server error: %w", err)
		}
	}()

	go func() {
		logger.Info("starting health HTTP server", "port", cfg.HealthPort)
		if err := healthHTTPServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errCh <- fmt.Errorf("health HTTP server error: %w", err)
		}
	}()

	// Wait for shutdown signal
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	select {
	case sig := <-sigCh:
		logger.Info("received shutdown signal", "signal", sig)
	case err := <-errCh:
		logger.Error("server error", "error", err)
	}

	// Graceful shutdown
	logger.Info("shutting down servers")
	grpcServer.GracefulStop()

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer shutdownCancel()

	if err := healthHTTPServer.Shutdown(shutdownCtx); err != nil {
		logger.Error("error during health server shutdown", "error", err)
	}
	logger.Info("shutdown complete")
}

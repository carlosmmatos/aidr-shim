// Package config provides configuration management for the AIDR GCP shim.
package config

import (
	"fmt"
	"os"
	"strconv"
)

// Config holds the configuration for the AIDR GCP shim.
type Config struct {
	// AIRDBaseURL is the base URL for the AIDR API.
	// Example: https://api.crowdstrike.com/aidr/aiguard
	AIRDBaseURL string

	// AIRDToken is the bearer token for AIDR authentication.
	AIRDToken string

	// GRPCPort is the port for the gRPC server.
	GRPCPort int

	// HealthPort is the port for the health check HTTP server.
	HealthPort int

	// CollectorInstanceID is an optional identifier for this shim instance.
	CollectorInstanceID string

	// LogLevel controls logging verbosity.
	LogLevel string

	// DebugMode enables verbose logging of requests and responses.
	DebugMode bool

	// EchoMode bypasses AIDR and just logs payloads. Always allows requests.
	EchoMode bool
}

// Load reads configuration from environment variables.
func Load() (*Config, error) {
	cfg := &Config{
		GRPCPort:   8080,
		HealthPort: 8081,
		LogLevel:   "info",
	}

	// Required configuration
	cfg.AIRDBaseURL = os.Getenv("AIDR_BASE_URL")
	if cfg.AIRDBaseURL == "" {
		return nil, fmt.Errorf("AIDR_BASE_URL environment variable is required")
	}

	cfg.AIRDToken = os.Getenv("AIDR_TOKEN")
	if cfg.AIRDToken == "" {
		return nil, fmt.Errorf("AIDR_TOKEN environment variable is required")
	}

	// Optional configuration with defaults
	if port := os.Getenv("GRPC_PORT"); port != "" {
		p, err := strconv.Atoi(port)
		if err != nil {
			return nil, fmt.Errorf("invalid GRPC_PORT: %w", err)
		}
		cfg.GRPCPort = p
	}

	if port := os.Getenv("HEALTH_PORT"); port != "" {
		p, err := strconv.Atoi(port)
		if err != nil {
			return nil, fmt.Errorf("invalid HEALTH_PORT: %w", err)
		}
		cfg.HealthPort = p
	}

	cfg.CollectorInstanceID = os.Getenv("COLLECTOR_INSTANCE_ID")

	if level := os.Getenv("LOG_LEVEL"); level != "" {
		cfg.LogLevel = level
	}

	cfg.DebugMode = os.Getenv("DEBUG_MODE") == "true"
	cfg.EchoMode = os.Getenv("ECHO_MODE") == "true"

	return cfg, nil
}

// Package config provides configuration management for the AIDR GCP shim.
package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// Config holds the configuration for the AIDR GCP shim.
type Config struct {
	// AIDRCloud is the CrowdStrike Falcon AIDR cloud region (e.g. us-1, us-2, eu-1).
	AIDRCloud string

	// AIDRToken is the bearer token for AIDR authentication.
	AIDRToken string

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

	// FailureMode controls behavior when AIDR is unreachable or returns an error.
	// "allow" (default) lets requests through; "deny" blocks them.
	FailureMode string
}

// Load reads configuration from environment variables.
func Load() (*Config, error) {
	cfg := &Config{
		GRPCPort:    8080,
		HealthPort:  8081,
		LogLevel:    "info",
		FailureMode: "allow",
	}

	// Required configuration
	cloudStr := os.Getenv("AIDR_CLOUD")
	if cloudStr == "" {
		return nil, fmt.Errorf("AIDR_CLOUD environment variable is required")
	}
	cloudURL, err := parseCloud(cloudStr)
	if err != nil {
		return nil, fmt.Errorf("invalid AIDR_CLOUD: %w", err)
	}
	cfg.AIDRCloud = cloudURL

	cfg.AIDRToken = strings.TrimSpace(os.Getenv("AIDR_TOKEN"))
	if cfg.AIDRToken == "" {
		return nil, fmt.Errorf("AIDR_TOKEN environment variable is required")
	}

	// Optional configuration with defaults
	if port := os.Getenv("GRPC_PORT"); port != "" {
		p, err := strconv.Atoi(port)
		if err != nil {
			return nil, fmt.Errorf("invalid GRPC_PORT: %w", err)
		}
		if p < 1 || p > 65535 {
			return nil, fmt.Errorf("invalid GRPC_PORT %d: must be between 1 and 65535", p)
		}
		cfg.GRPCPort = p
	}

	if port := os.Getenv("HEALTH_PORT"); port != "" {
		p, err := strconv.Atoi(port)
		if err != nil {
			return nil, fmt.Errorf("invalid HEALTH_PORT: %w", err)
		}
		if p < 1 || p > 65535 {
			return nil, fmt.Errorf("invalid HEALTH_PORT %d: must be between 1 and 65535", p)
		}
		cfg.HealthPort = p
	}

	cfg.CollectorInstanceID = os.Getenv("COLLECTOR_INSTANCE_ID")

	if level := os.Getenv("LOG_LEVEL"); level != "" {
		switch level {
		case "debug", "info", "warn", "error":
			cfg.LogLevel = level
		default:
			return nil, fmt.Errorf("invalid LOG_LEVEL %q: must be one of debug, info, warn, error", level)
		}
	}

	cfg.DebugMode = os.Getenv("DEBUG_MODE") == "true"
	cfg.EchoMode = os.Getenv("ECHO_MODE") == "true"

	if cfg.EchoMode && os.Getenv("ALLOW_ECHO_MODE") != "true" {
		return nil, fmt.Errorf("ECHO_MODE=true requires ALLOW_ECHO_MODE=true as a safety guard")
	}

	if fm := os.Getenv("FAILURE_MODE"); fm != "" {
		switch fm {
		case "allow", "deny":
			cfg.FailureMode = fm
		default:
			return nil, fmt.Errorf("invalid FAILURE_MODE %q: must be \"allow\" or \"deny\"", fm)
		}
	}

	return cfg, nil
}

// parseCloud normalizes and validates a cloud region string.
// It accepts formats like "us-1", "Us-1", "US1", " us-1 ", etc.
func parseCloud(s string) (string, error) {
	normalized := strings.ToLower(strings.TrimSpace(s))
	stripped := strings.ReplaceAll(normalized, "-", "")

	switch stripped {
	case "us1":
		return "https://api.crowdstrike.com/aidr/aiguard", nil
	case "us2":
		return "https://api.us-2.crowdstrike.com/aidr/aiguard", nil
	case "eu1":
		return "https://api.eu-1.crowdstrike.com/aidr/aiguard", nil
	case "usgov1":
		return "https://api.laggar.gcw.crowdstrike.com/aidr/aiguard", nil
	case "usgov2":
		return "https://api.us-gov-2.crowdstrike.mil/aidr/aiguard", nil
	}

	return "", fmt.Errorf("unrecognized falcon cloud region: %q", s)
}

package config

import (
	"os"
	"testing"
)

func TestLoad_RequiredFields(t *testing.T) {
	// Clear environment
	os.Clearenv()

	// Missing AIDR_BASE_URL should fail
	_, err := Load()
	if err == nil {
		t.Fatal("expected error when AIDR_BASE_URL is missing")
	}

	// Set AIDR_BASE_URL but missing AIDR_TOKEN
	os.Setenv("AIDR_BASE_URL", "https://api.crowdstrike.com/aidr/aiguard")
	_, err = Load()
	if err == nil {
		t.Fatal("expected error when AIDR_TOKEN is missing")
	}

	// Set both required fields
	os.Setenv("AIDR_TOKEN", "test-token")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.AIRDBaseURL != "https://api.crowdstrike.com/aidr/aiguard" {
		t.Errorf("unexpected base URL: %s", cfg.AIRDBaseURL)
	}
	if cfg.AIRDToken != "test-token" {
		t.Errorf("unexpected token: %s", cfg.AIRDToken)
	}
}

func TestLoad_Defaults(t *testing.T) {
	os.Clearenv()
	os.Setenv("AIDR_BASE_URL", "https://api.crowdstrike.com/aidr/aiguard")
	os.Setenv("AIDR_TOKEN", "test-token")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.GRPCPort != 8080 {
		t.Errorf("expected default GRPC port 8080, got %d", cfg.GRPCPort)
	}
	if cfg.HealthPort != 8081 {
		t.Errorf("expected default health port 8081, got %d", cfg.HealthPort)
	}
	if cfg.LogLevel != "info" {
		t.Errorf("expected default log level 'info', got %s", cfg.LogLevel)
	}
	if cfg.CollectorInstanceID != "" {
		t.Errorf("expected empty collector instance ID, got %s", cfg.CollectorInstanceID)
	}
}

func TestLoad_CustomPorts(t *testing.T) {
	os.Clearenv()
	os.Setenv("AIDR_BASE_URL", "https://api.crowdstrike.com/aidr/aiguard")
	os.Setenv("AIDR_TOKEN", "test-token")
	os.Setenv("GRPC_PORT", "9090")
	os.Setenv("HEALTH_PORT", "9091")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.GRPCPort != 9090 {
		t.Errorf("expected GRPC port 9090, got %d", cfg.GRPCPort)
	}
	if cfg.HealthPort != 9091 {
		t.Errorf("expected health port 9091, got %d", cfg.HealthPort)
	}
}

func TestLoad_InvalidPorts(t *testing.T) {
	os.Clearenv()
	os.Setenv("AIDR_BASE_URL", "https://api.crowdstrike.com/aidr/aiguard")
	os.Setenv("AIDR_TOKEN", "test-token")
	os.Setenv("GRPC_PORT", "invalid")

	_, err := Load()
	if err == nil {
		t.Fatal("expected error for invalid GRPC_PORT")
	}

	os.Setenv("GRPC_PORT", "8080")
	os.Setenv("HEALTH_PORT", "invalid")

	_, err = Load()
	if err == nil {
		t.Fatal("expected error for invalid HEALTH_PORT")
	}
}

func TestLoad_OptionalFields(t *testing.T) {
	os.Clearenv()
	os.Setenv("AIDR_BASE_URL", "https://api.crowdstrike.com/aidr/aiguard")
	os.Setenv("AIDR_TOKEN", "test-token")
	os.Setenv("COLLECTOR_INSTANCE_ID", "my-instance")
	os.Setenv("LOG_LEVEL", "debug")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.CollectorInstanceID != "my-instance" {
		t.Errorf("expected collector instance ID 'my-instance', got %s", cfg.CollectorInstanceID)
	}
	if cfg.LogLevel != "debug" {
		t.Errorf("expected log level 'debug', got %s", cfg.LogLevel)
	}
}

func TestLoad_DebugModes(t *testing.T) {
	os.Clearenv()
	os.Setenv("AIDR_BASE_URL", "https://api.crowdstrike.com/aidr/aiguard")
	os.Setenv("AIDR_TOKEN", "test-token")

	// Default: both disabled
	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.DebugMode {
		t.Error("expected DebugMode to be false by default")
	}
	if cfg.EchoMode {
		t.Error("expected EchoMode to be false by default")
	}

	// Enable debug mode
	os.Setenv("DEBUG_MODE", "true")
	cfg, err = Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !cfg.DebugMode {
		t.Error("expected DebugMode to be true when DEBUG_MODE=true")
	}

	// Enable echo mode
	os.Setenv("ECHO_MODE", "true")
	cfg, err = Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !cfg.EchoMode {
		t.Error("expected EchoMode to be true when ECHO_MODE=true")
	}

	// Non-true values should be false
	os.Setenv("DEBUG_MODE", "false")
	os.Setenv("ECHO_MODE", "1")
	cfg, err = Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.DebugMode {
		t.Error("expected DebugMode to be false when DEBUG_MODE=false")
	}
	if cfg.EchoMode {
		t.Error("expected EchoMode to be false when ECHO_MODE=1 (must be 'true')")
	}
}

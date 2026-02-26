package server

import (
	"context"
	"encoding/hex"
	"testing"
)

func TestWithRequestID(t *testing.T) {
	t.Parallel()
	ctx := WithRequestID(context.Background())
	id := GetRequestID(ctx)
	if id == "" {
		t.Fatal("expected non-empty request ID in context")
	}
}

func TestGetRequestID(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		ctx  context.Context
		want string
	}{
		{
			name: "missing request ID returns empty string",
			ctx:  context.Background(),
			want: "",
		},
		{
			name: "round-trip returns consistent value",
			ctx:  context.WithValue(context.Background(), requestIDKey, "test-id-123"),
			want: "test-id-123",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := GetRequestID(tt.ctx)
			if got != tt.want {
				t.Errorf("GetRequestID() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestGenerateRequestID_Format(t *testing.T) {
	t.Parallel()
	id := generateRequestID()

	if len(id) != 32 {
		t.Errorf("expected 32-char hex string, got %d chars: %q", len(id), id)
	}

	if _, err := hex.DecodeString(id); err != nil {
		t.Errorf("expected valid hex string, got decode error: %v", err)
	}
}

func TestGenerateRequestID_Unique(t *testing.T) {
	t.Parallel()
	id1 := generateRequestID()
	id2 := generateRequestID()

	if id1 == id2 {
		t.Errorf("expected unique IDs, both were %q", id1)
	}
}

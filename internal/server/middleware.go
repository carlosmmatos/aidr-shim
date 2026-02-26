// Package server provides middleware for the gRPC service.
package server

import (
	"context"
	"crypto/rand"
	"encoding/hex"
)

type contextKey string

const requestIDKey contextKey = "request_id"

// WithRequestID adds a request ID to the context.
func WithRequestID(ctx context.Context) context.Context {
	return context.WithValue(ctx, requestIDKey, generateRequestID())
}

// GetRequestID extracts the request ID from context.
func GetRequestID(ctx context.Context) string {
	if id, ok := ctx.Value(requestIDKey).(string); ok {
		return id
	}
	return ""
}

// generateRequestID generates a random request ID using crypto/rand.
func generateRequestID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		// Fallback to a simpler ID if crypto/rand fails
		return "unknown"
	}
	return hex.EncodeToString(b)
}

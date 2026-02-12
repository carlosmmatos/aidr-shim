// Package server implements the Envoy ext_proc gRPC service for AIDR integration.
package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/crowdstrike/aidr-go"
	"github.com/crowdstrike/aidr-go/packages/param"
)

// AIRDClient defines the interface for AIDR operations.
// This allows for mocking in tests.
type AIRDClient interface {
	GuardChatCompletions(ctx context.Context, params aidr.AIGuardGuardChatCompletionsParams) (*aidr.AIGuardGuardChatCompletionsResponse, error)
}

// aidrClientWrapper wraps the real AIDR client to implement AIRDClient.
type aidrClientWrapper struct {
	client *aidr.Client
}

func (w *aidrClientWrapper) GuardChatCompletions(ctx context.Context, params aidr.AIGuardGuardChatCompletionsParams) (*aidr.AIGuardGuardChatCompletionsResponse, error) {
	return w.client.AIGuard.GuardChatCompletions(ctx, params)
}

// NewAIRDClientWrapper creates a new wrapper around the AIDR client.
func NewAIRDClientWrapper(client *aidr.Client) AIRDClient {
	return &aidrClientWrapper{client: client}
}

// CalloutService implements the Envoy ExternalProcessor gRPC service.
type CalloutService struct {
	extprocv3.UnimplementedExternalProcessorServer
	aidrClient          AIRDClient
	collectorInstanceID string
	logger              *slog.Logger
	debugMode           bool
	echoMode            bool
}

// NewCalloutServiceParams contains parameters for creating a CalloutService.
type CalloutServiceParams struct {
	AIRDClient          AIRDClient
	CollectorInstanceID string
	Logger              *slog.Logger
	DebugMode           bool
	EchoMode            bool
}

// NewCalloutService creates a new CalloutService.
func NewCalloutService(cs CalloutServiceParams) *CalloutService {
	return &CalloutService{
		aidrClient:          cs.AIRDClient,
		collectorInstanceID: cs.CollectorInstanceID,
		logger:              cs.Logger,
		debugMode:           cs.DebugMode,
		echoMode:            cs.EchoMode,
	}
}

// Process implements the bidirectional streaming RPC for ext_proc.
func (s *CalloutService) Process(stream extprocv3.ExternalProcessor_ProcessServer) error {
	ctx := WithRequestID(stream.Context())
	requestID := GetRequestID(ctx)

	for {
		req, err := stream.Recv()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			// Context cancellation is normal when client disconnects
			if errors.Is(err, context.Canceled) || status.Code(err) == codes.Canceled {
				s.logger.Debug("stream closed by client", "request_id", requestID)
				return nil
			}
			s.logger.Error("error receiving request", "error", err, "request_id", requestID)
			return status.Errorf(codes.Internal, "error receiving request: %v", err)
		}

		var resp *extprocv3.ProcessingResponse

		switch v := req.Request.(type) {
		case *extprocv3.ProcessingRequest_RequestHeaders:
			resp = s.handleRequestHeaders(ctx, v.RequestHeaders)
		case *extprocv3.ProcessingRequest_RequestBody:
			resp, err = s.handleRequestBody(ctx, v.RequestBody)
			if err != nil {
				s.logger.Error("processing request body failed",
					"error", err,
					"request_id", requestID,
				)
				resp = s.allowResponse(true)
			}
		case *extprocv3.ProcessingRequest_ResponseHeaders:
			resp = s.handleResponseHeaders(ctx, v.ResponseHeaders)
		case *extprocv3.ProcessingRequest_ResponseBody:
			resp, err = s.handleResponseBody(ctx, v.ResponseBody)
			if err != nil {
				s.logger.Error("processing response body failed",
					"error", err,
					"request_id", requestID,
				)
				resp = s.allowResponse(false)
			}
		default:
			resp = &extprocv3.ProcessingResponse{}
		}

		if err := stream.Send(resp); err != nil {
			s.logger.Error("error sending response", "error", err, "request_id", requestID)
			return status.Errorf(codes.Internal, "error sending response: %v", err)
		}
	}
}

func (s *CalloutService) handleRequestHeaders(_ context.Context, _ *extprocv3.HttpHeaders) *extprocv3.ProcessingResponse {
	// Continue processing headers, wait for body
	return &extprocv3.ProcessingResponse{
		Response: &extprocv3.ProcessingResponse_RequestHeaders{
			RequestHeaders: &extprocv3.HeadersResponse{},
		},
	}
}

func (s *CalloutService) handleResponseHeaders(_ context.Context, _ *extprocv3.HttpHeaders) *extprocv3.ProcessingResponse {
	// Continue processing headers, wait for body
	return &extprocv3.ProcessingResponse{
		Response: &extprocv3.ProcessingResponse_ResponseHeaders{
			ResponseHeaders: &extprocv3.HeadersResponse{},
		},
	}
}

func (s *CalloutService) handleRequestBody(ctx context.Context, body *extprocv3.HttpBody) (*extprocv3.ProcessingResponse, error) {
	return s.processBody(ctx, body.Body, aidr.AIGuardGuardChatCompletionsParamsEventTypeInput, true)
}

func (s *CalloutService) handleResponseBody(ctx context.Context, body *extprocv3.HttpBody) (*extprocv3.ProcessingResponse, error) {
	return s.processBody(ctx, body.Body, aidr.AIGuardGuardChatCompletionsParamsEventTypeOutput, false)
}

func (s *CalloutService) processBody(ctx context.Context, body []byte, eventType aidr.AIGuardGuardChatCompletionsParamsEventType, isRequest bool) (*extprocv3.ProcessingResponse, error) {
	eventTypeStr := "request"
	if !isRequest {
		eventTypeStr = "response"
	}

	// Debug logging of incoming body
	if s.debugMode {
		s.logger.Debug("processing body",
			"type", eventTypeStr,
			"body_size", len(body),
		)
	}

	// Parse the body as JSON to extract guard_input structure
	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, fmt.Errorf("parse JSON body: %w", err)
	}

	// Echo mode: log and allow without calling AIDR
	if s.echoMode {
		s.logger.Info("echo mode: bypassing AIDR",
			"type", eventTypeStr,
			"body_size", len(body),
		)
		return s.allowResponse(isRequest), nil
	}

	// Build guard_input - the SDK accepts any as guard_input so we pass the parsed payload
	// which typically contains messages, tools, and other fields per the AI chat format
	guardInput := s.buildGuardInput(payload)

	// Call AIDR
	params := aidr.AIGuardGuardChatCompletionsParams{
		GuardInput: guardInput,
		EventType:  eventType,
	}

	if s.collectorInstanceID != "" {
		params.CollectorInstanceID = param.NewOpt(s.collectorInstanceID)
	}

	if s.debugMode {
		s.logger.Debug("calling AIDR API",
			"event_type", string(eventType),
		)
	}

	aidrResp, err := s.aidrClient.GuardChatCompletions(ctx, params)
	if err != nil {
		return nil, fmt.Errorf("call AIDR API: %w", err)
	}

	if s.debugMode {
		s.logger.Debug("AIDR API response",
			"blocked", aidrResp.Result.Blocked,
			"transformed", aidrResp.Result.Transformed,
		)
	}

	// Check for blocked content
	if aidrResp.Result.Blocked {
		s.logger.Info("request blocked by AIDR policy")
		resp, err := s.blockedResponse(isRequest)
		if err != nil {
			return nil, fmt.Errorf("create blocked response: %w", err)
		}
		return resp, nil
	}

	// Check for transformed content
	if aidrResp.Result.Transformed && aidrResp.Result.GuardOutput != nil {
		s.logger.Info("request transformed by AIDR policy")
		if s.debugMode {
			s.logger.Debug("transformed output", "has_guard_output", true)
		}
		resp, err := s.transformedResponse(aidrResp.Result.GuardOutput, isRequest)
		if err != nil {
			return nil, fmt.Errorf("create transformed response: %w", err)
		}
		return resp, nil
	}

	// Allow unchanged
	return s.allowResponse(isRequest), nil
}

// buildGuardInput constructs the guard_input structure from the incoming payload.
// The AIDR API expects guard_input to contain fields like "messages" and "tools"
// following the OpenAI Chat Completions format.
func (s *CalloutService) buildGuardInput(payload map[string]any) map[string]any {
	guardInput := make(map[string]any)

	// Strategy 1: Extract messages and tools directly
	if s.extractMessagesAndTools(payload, guardInput) {
		return guardInput
	}

	// Strategy 2: Convert simple prompt to messages format
	if s.convertPromptToMessages(payload, guardInput) {
		return guardInput
	}

	// Strategy 3: Pass entire payload as-is
	return payload
}

// extractMessagesAndTools extracts messages and tools fields from the payload.
func (s *CalloutService) extractMessagesAndTools(payload, guardInput map[string]any) bool {
	hasContent := false
	if messages, ok := payload["messages"]; ok {
		guardInput["messages"] = messages
		hasContent = true
	}
	if tools, ok := payload["tools"]; ok {
		guardInput["tools"] = tools
		hasContent = true
	}
	return hasContent
}

// convertPromptToMessages converts a simple prompt field to messages format.
func (s *CalloutService) convertPromptToMessages(payload, guardInput map[string]any) bool {
	prompt, hasPrompt := payload["prompt"]
	if !hasPrompt {
		return false
	}

	if model, ok := payload["model"]; ok {
		guardInput["model"] = model
	}
	guardInput["messages"] = []map[string]any{
		{"role": "user", "content": prompt},
	}
	return true
}

func (s *CalloutService) allowResponse(isRequest bool) *extprocv3.ProcessingResponse {
	if isRequest {
		return &extprocv3.ProcessingResponse{
			Response: &extprocv3.ProcessingResponse_RequestBody{
				RequestBody: &extprocv3.BodyResponse{
					Response: &extprocv3.CommonResponse{},
				},
			},
		}
	}
	return &extprocv3.ProcessingResponse{
		Response: &extprocv3.ProcessingResponse_ResponseBody{
			ResponseBody: &extprocv3.BodyResponse{
				Response: &extprocv3.CommonResponse{},
			},
		},
	}
}

func (s *CalloutService) blockedResponse(isRequest bool) (*extprocv3.ProcessingResponse, error) {
	var blockMessage string
	if isRequest {
		blockMessage = "Request blocked by security policy"
	} else {
		blockMessage = "Response blocked by security policy"
	}

	bodyBytes, err := json.Marshal(map[string]string{
		"error": blockMessage,
	})
	if err != nil {
		return nil, fmt.Errorf("marshal blocked response: %w", err)
	}

	return &extprocv3.ProcessingResponse{
		Response: &extprocv3.ProcessingResponse_ImmediateResponse{
			ImmediateResponse: &extprocv3.ImmediateResponse{
				Status: &typev3.HttpStatus{
					Code: typev3.StatusCode_Forbidden,
				},
				Headers: &extprocv3.HeaderMutation{
					SetHeaders: []*corev3.HeaderValueOption{
						{
							Header: &corev3.HeaderValue{
								Key:   "content-type",
								Value: "application/json",
							},
						},
					},
				},
				Body: bodyBytes,
			},
		},
	}, nil
}

func (s *CalloutService) transformedResponse(guardOutput any, isRequest bool) (*extprocv3.ProcessingResponse, error) {
	// Marshal the guard output back to JSON
	bodyBytes, err := json.Marshal(guardOutput)
	if err != nil {
		return nil, fmt.Errorf("marshal guard output: %w", err)
	}

	bodyMutation := &extprocv3.BodyMutation{
		Mutation: &extprocv3.BodyMutation_Body{
			Body: bodyBytes,
		},
	}

	if isRequest {
		return &extprocv3.ProcessingResponse{
			Response: &extprocv3.ProcessingResponse_RequestBody{
				RequestBody: &extprocv3.BodyResponse{
					Response: &extprocv3.CommonResponse{
						BodyMutation: bodyMutation,
					},
				},
			},
		}, nil
	}
	return &extprocv3.ProcessingResponse{
		Response: &extprocv3.ProcessingResponse_ResponseBody{
			ResponseBody: &extprocv3.BodyResponse{
				Response: &extprocv3.CommonResponse{
					BodyMutation: bodyMutation,
				},
			},
		},
	}, nil
}

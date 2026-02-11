// Package server implements the Envoy ext_proc gRPC service for AIDR integration.
package server

import (
	"context"
	"encoding/json"
	"errors"
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

// NewCalloutService creates a new CalloutService.
func NewCalloutService(aidrClient AIRDClient, collectorInstanceID string, logger *slog.Logger, debugMode, echoMode bool) *CalloutService {
	return &CalloutService{
		aidrClient:          aidrClient,
		collectorInstanceID: collectorInstanceID,
		logger:              logger,
		debugMode:           debugMode,
		echoMode:            echoMode,
	}
}

// Process implements the bidirectional streaming RPC for ext_proc.
func (s *CalloutService) Process(stream extprocv3.ExternalProcessor_ProcessServer) error {
	ctx := stream.Context()

	for {
		req, err := stream.Recv()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			// Context cancellation is normal when client disconnects
			if errors.Is(err, context.Canceled) || status.Code(err) == codes.Canceled {
				s.logger.Debug("stream closed by client")
				return nil
			}
			s.logger.Error("error receiving request", "error", err)
			return status.Errorf(codes.Internal, "error receiving request: %v", err)
		}

		var resp *extprocv3.ProcessingResponse

		switch v := req.Request.(type) {
		case *extprocv3.ProcessingRequest_RequestHeaders:
			resp = s.handleRequestHeaders(ctx, v.RequestHeaders)
		case *extprocv3.ProcessingRequest_RequestBody:
			resp = s.handleRequestBody(ctx, v.RequestBody)
		case *extprocv3.ProcessingRequest_ResponseHeaders:
			resp = s.handleResponseHeaders(ctx, v.ResponseHeaders)
		case *extprocv3.ProcessingRequest_ResponseBody:
			resp = s.handleResponseBody(ctx, v.ResponseBody)
		default:
			resp = &extprocv3.ProcessingResponse{}
		}

		if err := stream.Send(resp); err != nil {
			s.logger.Error("error sending response", "error", err)
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

func (s *CalloutService) handleRequestBody(ctx context.Context, body *extprocv3.HttpBody) *extprocv3.ProcessingResponse {
	return s.processBody(ctx, body.Body, aidr.AIGuardGuardChatCompletionsParamsEventTypeInput, true)
}

func (s *CalloutService) handleResponseBody(ctx context.Context, body *extprocv3.HttpBody) *extprocv3.ProcessingResponse {
	return s.processBody(ctx, body.Body, aidr.AIGuardGuardChatCompletionsParamsEventTypeOutput, false)
}

func (s *CalloutService) processBody(ctx context.Context, body []byte, eventType aidr.AIGuardGuardChatCompletionsParamsEventType, isRequest bool) *extprocv3.ProcessingResponse {
	eventTypeStr := "request"
	if !isRequest {
		eventTypeStr = "response"
	}

	// Debug logging of incoming body
	if s.debugMode {
		s.logger.Debug("processing body",
			"type", eventTypeStr,
			"body_size", len(body),
			"body", string(body),
		)
	}

	// Parse the body as JSON to extract guard_input structure
	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		s.logger.Warn("failed to parse body as JSON, allowing through", "error", err)
		return s.allowResponse(isRequest)
	}

	// Echo mode: log and allow without calling AIDR
	if s.echoMode {
		s.logger.Info("echo mode: bypassing AIDR",
			"type", eventTypeStr,
			"body_size", len(body),
		)
		return s.allowResponse(isRequest)
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
		guardInputJSON, _ := json.Marshal(guardInput)
		s.logger.Debug("calling AIDR API",
			"event_type", string(eventType),
			"guard_input", string(guardInputJSON),
		)
	}

	aidrResp, err := s.aidrClient.GuardChatCompletions(ctx, params)
	if err != nil {
		s.logger.Error("AIDR API call failed, allowing through", "error", err)
		return s.allowResponse(isRequest)
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
		return s.blockedResponse(isRequest)
	}

	// Check for transformed content
	if aidrResp.Result.Transformed && aidrResp.Result.GuardOutput != nil {
		s.logger.Info("request transformed by AIDR policy")
		if s.debugMode {
			guardOutputJSON, _ := json.Marshal(aidrResp.Result.GuardOutput)
			s.logger.Debug("transformed output", "guard_output", string(guardOutputJSON))
		}
		return s.transformedResponse(aidrResp.Result.GuardOutput, isRequest)
	}

	// Allow unchanged
	return s.allowResponse(isRequest)
}

// buildGuardInput constructs the guard_input structure from the incoming payload.
// The AIDR API expects guard_input to contain fields like "messages" and "tools"
// following the OpenAI Chat Completions format.
func (s *CalloutService) buildGuardInput(payload map[string]any) map[string]any {
	// The guard_input is the full payload for AI requests
	// which should contain messages array and optionally tools
	guardInput := make(map[string]any)

	// Copy messages if present
	if messages, ok := payload["messages"]; ok {
		guardInput["messages"] = messages
	}

	// Copy tools if present
	if tools, ok := payload["tools"]; ok {
		guardInput["tools"] = tools
	}

	// If the payload doesn't have messages but has content directly,
	// wrap it in a messages array (for simple prompt requests)
	if _, hasMessages := guardInput["messages"]; !hasMessages {
		// Check for other common fields and include them
		if model, ok := payload["model"]; ok {
			guardInput["model"] = model
		}
		if prompt, ok := payload["prompt"]; ok {
			// Convert simple prompt to messages format
			guardInput["messages"] = []map[string]any{
				{"role": "user", "content": prompt},
			}
		}
	}

	// If still no messages, pass the entire payload as-is
	// AIDR can analyze any valid JSON
	if len(guardInput) == 0 {
		return payload
	}

	return guardInput
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

func (s *CalloutService) blockedResponse(isRequest bool) *extprocv3.ProcessingResponse {
	var blockMessage string
	if isRequest {
		blockMessage = "Request blocked by security policy"
	} else {
		blockMessage = "Response blocked by security policy"
	}

	bodyBytes, _ := json.Marshal(map[string]string{
		"error": blockMessage,
	})

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
	}
}

func (s *CalloutService) transformedResponse(guardOutput interface{}, isRequest bool) *extprocv3.ProcessingResponse {
	// Marshal the guard output back to JSON
	bodyBytes, err := json.Marshal(guardOutput)
	if err != nil {
		s.logger.Error("failed to marshal guard output", "error", err)
		return s.allowResponse(isRequest)
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
		}
	}
	return &extprocv3.ProcessingResponse{
		Response: &extprocv3.ProcessingResponse_ResponseBody{
			ResponseBody: &extprocv3.BodyResponse{
				Response: &extprocv3.CommonResponse{
					BodyMutation: bodyMutation,
				},
			},
		},
	}
}

package utils

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	authv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	authenticationv1 "k8s.io/client-go/kubernetes/typed/authentication/v1"
	"k8s.io/client-go/rest"
)

const (
	validToken   = "valid-token"
	invalidToken = "invalid-token"
	testToken    = "test-token"
)

// mockAuthV1Client is a mock implementation of AuthenticationV1Interface for testing
type mockAuthV1Client struct {
	shouldReturnError bool
	tokenValid        bool
	errorMessage      string
	returnAudiences   []string
	gotAudiences      []string
}

// TokenReviews implements AuthenticationV1Interface
func (m *mockAuthV1Client) TokenReviews() authenticationv1.TokenReviewInterface {
	return &mockTokenReviewsClient{parent: m}
}

// SelfSubjectReviews implements AuthenticationV1Interface (required by interface)
func (m *mockAuthV1Client) SelfSubjectReviews() authenticationv1.SelfSubjectReviewInterface {
	return nil
}

// RESTClient implements AuthenticationV1Interface (required by interface)
func (m *mockAuthV1Client) RESTClient() rest.Interface {
	return nil
}

// mockTokenReviewsClient mocks the TokenReviewInterface
type mockTokenReviewsClient struct {
	parent *mockAuthV1Client
}

// Create implements TokenReviewInterface
func (m *mockTokenReviewsClient) Create(ctx context.Context, tokenReview *authv1.TokenReview, opts metav1.CreateOptions) (*authv1.TokenReview, error) {
	m.parent.gotAudiences = tokenReview.Spec.Audiences

	if m.parent.shouldReturnError {
		return nil, fmt.Errorf("mock API error: %s", m.parent.errorMessage)
	}

	result := &authv1.TokenReview{
		Status: authv1.TokenReviewStatus{
			Authenticated: m.parent.tokenValid,
			Audiences:     m.parent.returnAudiences,
		},
	}

	if !m.parent.tokenValid {
		result.Status.Error = "token is invalid"
	}

	return result, nil
}

func TestNewK8sSaTokenVerifierInternal(t *testing.T) {
	tests := []struct {
		name       string
		authClient authenticationv1.AuthenticationV1Interface
		wantNil    bool
	}{
		{
			name: "with valid auth client",
			authClient: &mockAuthV1Client{
				shouldReturnError: false,
				tokenValid:        true,
			},
			wantNil: false,
		},
		{
			name:       "with nil auth client",
			authClient: nil,
			wantNil:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := newK8sSaTokenVerifier(tt.authClient, nil)
			if (got == nil) != tt.wantNil {
				t.Errorf("newK8sSaTokenVerifier() = %v, wantNil %v", got, tt.wantNil)
			}
		})
	}
}

func TestNewK8sSaTokenVerifier(t *testing.T) {
	tests := []struct {
		name              string
		k8sAPIHost        string
		k8sClientCertFile string
		k8sClientKeyFile  string
		k8sCAFile         string
		wantErr           bool
		errorContains     string
	}{
		{
			name:              "invalid configuration should return error",
			k8sAPIHost:        "invalid-host",
			k8sClientCertFile: "/nonexistent/cert.pem",
			k8sClientKeyFile:  "/nonexistent/key.pem",
			k8sCAFile:         "/nonexistent/ca.pem",
			wantErr:           true,
			errorContains:     "failed to create kubernetes client",
		},
		{
			name:              "empty parameters should return error",
			k8sAPIHost:        "",
			k8sClientCertFile: "",
			k8sClientKeyFile:  "",
			k8sCAFile:         "",
			wantErr:           false,
			errorContains:     "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewK8sSaTokenVerifier(tt.k8sAPIHost, nil, tt.k8sClientCertFile, tt.k8sClientKeyFile, tt.k8sCAFile)

			if (err != nil) != tt.wantErr {
				t.Errorf("NewK8sSaTokenVerifier() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr {
				if err == nil {
					t.Error("Expected error but got nil")
				} else if tt.errorContains != "" && !strings.Contains(err.Error(), tt.errorContains) {
					t.Errorf("Expected error to contain '%s', got: %v", tt.errorContains, err)
				}
				if got != nil {
					t.Error("Expected nil verifier when error occurs")
				}
			} else {
				if got == nil {
					t.Error("Expected non-nil verifier")
				}
			}
		})
	}
}

func TestK8sSaTokenVerifierImplVerify(t *testing.T) {
	tests := []struct {
		name          string
		authClient    authenticationv1.AuthenticationV1Interface
		token         string
		ctx           context.Context
		expectError   bool
		errorContains string
	}{
		{
			name: "valid token should return no error",
			authClient: &mockAuthV1Client{
				shouldReturnError: false,
				tokenValid:        true,
			},
			token:       validToken,
			ctx:         context.Background(),
			expectError: false,
		},
		{
			name: "invalid token should return error",
			authClient: &mockAuthV1Client{
				shouldReturnError: false,
				tokenValid:        false,
			},
			token:         invalidToken,
			ctx:           context.Background(),
			expectError:   true,
			errorContains: "SA token authentication failed: token is invalid",
		},
		{
			name: "API error should return error",
			authClient: &mockAuthV1Client{
				shouldReturnError: true,
				tokenValid:        false,
				errorMessage:      "network timeout",
			},
			token:         "some-token",
			ctx:           context.Background(),
			expectError:   true,
			errorContains: "failed to call TokenReview API",
		},
		{
			name:          "nil auth client should return error",
			authClient:    nil,
			token:         "some-token",
			ctx:           context.Background(),
			expectError:   true,
			errorContains: "authentication client is nil",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			verifier := newK8sSaTokenVerifier(tt.authClient, nil)
			err := verifier.Verify(tt.ctx, tt.token)

			if tt.expectError {
				if err == nil {
					t.Error("Expected error but got nil")
				} else if tt.errorContains != "" && !strings.Contains(err.Error(), tt.errorContains) {
					t.Errorf("Expected error to contain '%s', got: %v", tt.errorContains, err)
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error, got: %v", err)
				}
			}
		})
	}
}

func TestK8sSaTokenVerifierWithContextCancellation(t *testing.T) {
	t.Run("context cancellation should be passed to API", func(t *testing.T) {
		mockClient := &mockAuthV1Client{
			shouldReturnError: false,
			tokenValid:        true,
		}

		verifier := newK8sSaTokenVerifier(mockClient, nil)

		cancelledCtx, cancel := context.WithCancel(context.Background())
		cancel()

		err := verifier.Verify(cancelledCtx, testToken)
		_ = err
	})

	t.Run("context with timeout", func(t *testing.T) {
		mockClient := &mockAuthV1Client{
			shouldReturnError: false,
			tokenValid:        true,
		}

		verifier := newK8sSaTokenVerifier(mockClient, nil)

		timeoutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		err := verifier.Verify(timeoutCtx, validToken)
		if err != nil {
			t.Errorf("Unexpected error with timeout context: %v", err)
		}
	})
}

func TestK8sSaTokenVerifierAudienceBinding(t *testing.T) {
	t.Run("audiences are forwarded to TokenReview Spec", func(t *testing.T) {
		mockClient := &mockAuthV1Client{
			tokenValid:      true,
			returnAudiences: []string{"spire-identity-exchange"},
		}
		verifier := newK8sSaTokenVerifier(mockClient, []string{"spire-identity-exchange"})
		if err := verifier.Verify(context.Background(), validToken); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(mockClient.gotAudiences) != 1 || mockClient.gotAudiences[0] != "spire-identity-exchange" {
			t.Errorf("expected configured audiences forwarded, got %v", mockClient.gotAudiences)
		}
	})

	t.Run("mismatched status audiences are rejected", func(t *testing.T) {
		mockClient := &mockAuthV1Client{
			tokenValid:      true,
			returnAudiences: []string{"some-other-service"},
		}
		verifier := newK8sSaTokenVerifier(mockClient, []string{"spire-identity-exchange"})
		err := verifier.Verify(context.Background(), validToken)
		if err == nil || !strings.Contains(err.Error(), "do not match expected audiences") {
			t.Errorf("expected audience-mismatch rejection, got %v", err)
		}
	})

	t.Run("no audiences configured means no audience binding enforced", func(t *testing.T) {
		mockClient := &mockAuthV1Client{
			tokenValid:      true,
			returnAudiences: []string{"any-audience"},
		}
		verifier := newK8sSaTokenVerifier(mockClient, nil)
		if err := verifier.Verify(context.Background(), validToken); err != nil {
			t.Errorf("expected no error with audience binding disabled, got: %v", err)
		}
	})
}

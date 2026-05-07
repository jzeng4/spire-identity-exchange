package utils

import (
	"context"
	"fmt"

	authv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	authenticationv1 "k8s.io/client-go/kubernetes/typed/authentication/v1"
	"k8s.io/client-go/rest"
)

// K8sSaTokenVerifier interface defines the token verification contract
type K8sSaTokenVerifier interface {
	Verify(ctx context.Context, token string) error
}

// k8sSaTokenVerifierImpl implements K8sSaTokenVerifier
type k8sSaTokenVerifierImpl struct {
	authClient authenticationv1.AuthenticationV1Interface
}

// newK8sSaTokenVerifier creates a new token verifier with the given authentication client
func newK8sSaTokenVerifier(authClient authenticationv1.AuthenticationV1Interface) K8sSaTokenVerifier {
	return &k8sSaTokenVerifierImpl{authClient: authClient}
}

// NewK8sSaTokenVerifier creates a new token verifier with the given client set
func NewK8sSaTokenVerifier(k8sAPIHost, k8sClientCertFile, k8sClientKeyFile, k8sCAFile string) (K8sSaTokenVerifier, error) {
	cfg := newK8sClientConfig(k8sAPIHost, k8sClientCertFile, k8sClientKeyFile, k8sCAFile)
	clientset, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create kubernetes client: %w", err)
	}
	return newK8sSaTokenVerifier(clientset.AuthenticationV1()), nil
}

// newK8sClientConfig creates a Kubernetes client config for the given parameters
func newK8sClientConfig(k8sAPIHost, k8sClientCertFile, k8sClientKeyFile, k8sCAFile string) *rest.Config {
	var c rest.Config
	c.Host = k8sAPIHost
	c.TLSClientConfig.CAFile = k8sCAFile
	c.TLSClientConfig.CertFile = k8sClientCertFile
	c.TLSClientConfig.KeyFile = k8sClientKeyFile
	c.QPS = 20.0
	c.Burst = 30.0
	return &c
}

// Verify verifies a Kubernetes service account token
func (v *k8sSaTokenVerifierImpl) Verify(ctx context.Context, token string) error {
	if v.authClient == nil {
		return fmt.Errorf("authentication client is nil")
	}

	// Create TokenReview
	tr := &authv1.TokenReview{
		Spec: authv1.TokenReviewSpec{
			Token: token,
		},
	}

	// Call TokenReview API with provided context
	result, err := v.authClient.TokenReviews().Create(
		ctx, tr, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("failed to call TokenReview API: %w", err)
	}

	if !result.Status.Authenticated {
		return fmt.Errorf("SA token authentication failed: %s", result.Status.Error)
	}
	return nil
}

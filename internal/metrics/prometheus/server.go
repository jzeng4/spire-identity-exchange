package prometheus

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/spiffe/spire-identity-exchange/internal/metrics"
	"go.uber.org/zap"
)

type MetricsServer struct {
	Port     int
	Registry *prometheus.Registry
	// Entity that is being monitored
	Entity string
	// Metrics for the entity
	Metrics metrics.Metrics
}

type Option func(*MetricsServer)

// WithPort sets the port for the metrics server
func WithPort(port int) Option {
	return func(s *MetricsServer) {
		s.Port = port
	}
}

// NewMetricsServer creates a new metrics server
func NewMetricsServer(opts ...Option) *MetricsServer {
	metricsServer := &MetricsServer{
		Registry: prometheus.NewRegistry(),
	}

	for _, opt := range opts {
		opt(metricsServer)
	}

	return metricsServer
}

// For sets the app name and metrics for the app
func (m *MetricsServer) For(entity string, metrics metrics.Metrics) *MetricsServer {
	m.Entity = entity
	m.Metrics = metrics
	return m
}

// Start starts the metrics server and blocks until ctx is cancelled or the server fails.
// Returns nil on clean shutdown, or an error if the server failed to start or serve.
func (m *MetricsServer) Start(ctx context.Context, logger *zap.Logger) error {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(m.Registry, promhttp.HandlerOpts{}))

	addr := fmt.Sprintf(":%d", m.Port)
	// Bound per-connection timeouts so a slow or stalled scraper can't pin file
	// descriptors and goroutines indefinitely. Prometheus scrapes are short-lived
	// GET requests; these limits are well beyond what a healthy scrape needs.
	server := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	logger.Info("Starting prometheus server", zap.String("entity", m.Entity), zap.String("addr", addr))

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			logger.Warn("metrics server shutdown", zap.Error(err))
		}
	}()

	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("metrics server error: %w", err)
	}
	return nil
}

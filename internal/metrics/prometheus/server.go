package prometheus

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/sirupsen/logrus"
	"github.com/spiffe/spire-identity-exchange/internal/metrics"
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

// Start starts the metrics server and blocks until ctx is cancelled.
func (m *MetricsServer) Start(ctx context.Context) {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(m.Registry, promhttp.HandlerOpts{}))

	addr := fmt.Sprintf(":%d", m.Port)
	server := &http.Server{Addr: addr, Handler: mux}

	logrus.SetFormatter(&logrus.JSONFormatter{})
	logrus.Infof("Starting prometheus server for %s on %s ...", m.Entity, addr)

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			logrus.Warnf("metrics server shutdown: %v", err)
		}
	}()

	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		logrus.Fatalf("metrics server error: %v", err)
	}
}

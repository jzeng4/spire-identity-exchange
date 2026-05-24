package prometheus

import (
	"github.com/spiffe/spire-identity-exchange/internal/metrics"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
)

// PluginMetrics implements the metrics.Metrics interface using Prometheus.
type PluginMetrics struct {
	OperationCount    *prometheus.CounterVec
	OperationDuration *prometheus.HistogramVec
}

// Ensure PluginMetrics implements metrics.Metrics interface
var _ metrics.Metrics = (*PluginMetrics)(nil)

// NewPluginMetrics creates a new PluginMetrics and registers
// its metrics with the provided registry.
func NewPluginMetrics(reg *prometheus.Registry, subSystem string) *PluginMetrics {
	m := &PluginMetrics{
		OperationCount: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "pki",
			Subsystem: subSystem,
			Name:      "operation_count",
			Help:      "Number of operation calls with status",
		}, []string{"component", "plugin", "operation", "status"}),
		OperationDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: "pki",
			Subsystem: subSystem,
			Name:      "operation_duration_seconds",
			Help:      "Duration of operations with status",
			Buckets:   []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10},
		}, []string{"component", "plugin", "operation", "status"}),
	}

	reg.MustRegister(m.OperationCount)
	reg.MustRegister(m.OperationDuration)

	prefixedReg := prometheus.WrapRegistererWithPrefix("pki_"+subSystem+"_", reg)
	prefixedReg.MustRegister(collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
	prefixedReg.MustRegister(collectors.NewGoCollector())

	return m
}

func (m *PluginMetrics) IncOperationCount(component, plugin, operation, status string) {
	m.OperationCount.WithLabelValues(component, plugin, operation, status).Inc()
}

func (m *PluginMetrics) ObserveOperationDuration(component, plugin, operation, status string, duration float64) {
	m.OperationDuration.WithLabelValues(component, plugin, operation, status).Observe(duration)
}

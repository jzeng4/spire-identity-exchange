package metrics

// Metrics defines the interface for recording plugin metrics.
// This interface supports both Prometheus and OpenTelemetry implementations.
type Metrics interface {
	// IncOperationCount increments the operation count metric
	IncOperationCount(component, plugin, operation, status string)
	// ObserveOperationDuration records the duration of an operation
	ObserveOperationDuration(component, plugin, operation, status string, duration float64)
}

package plugin

import "github.com/prometheus/client_golang/prometheus"

func init() {
	registerPrometheusMetrics()
}

func registerPrometheusMetrics() {
	prometheus.MustRegister(kmsOperationCounter)
	prometheus.MustRegister(kmsLatencyMetric)
}

var (
	kmsOperationCounter = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "tang_encryption_provider_kms_operations_total",
			Help: "total tang encryption provider kms operations",
		},
		[]string{
			"status",
			"operation",
		},
	)

	kmsLatencyMetric = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "tang_encryption_provider_kms_operation_latency_ms",
			Help:    "Response latency in milliseconds for tang encryption provider kms operation ",
			Buckets: prometheus.ExponentialBuckets(2, 2, 14),
		},
		[]string{
			"status",
			"operation",
		},
	)
)

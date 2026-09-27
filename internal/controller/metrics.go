package controller

import (
	"github.com/prometheus/client_golang/prometheus"
	crmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"
)

var (
	// reconcileTotal counts IncidentPolicy reconciliation attempts.
	//
	// result should remain low-cardinality:
	// success
	// error
	reconcileTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "kubetriage",
			Subsystem: "incidentpolicy_controller",
			Name:      "reconcile_total",
			Help:      "Total number of IncidentPolicy reconciliation attempts.",
		},
		[]string{
			"result",
		},
	)

	// reconcileDuration measures how long an IncidentPolicy reconciliation
	// takes from entry to completion.
	reconcileDuration = prometheus.NewHistogram(
		prometheus.HistogramOpts{
			Namespace: "kubetriage",
			Subsystem: "incidentpolicy_controller",
			Name:      "reconcile_duration_seconds",
			Help:      "Duration of IncidentPolicy reconciliation in seconds.",
			Buckets:   prometheus.DefBuckets,
		},
	)

	// incidentsDetectedTotal counts detected incidents by supported
	// incident type.
	//
	// incident_type is intentionally bounded to the supported detector set:
	// CrashLoopBackOff
	// OOMKilled
	// ErrImagePull
	// ImagePullBackOff
	incidentsDetectedTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "kubetriage",
			Subsystem: "incident",
			Name:      "detected_total",
			Help:      "Total number of incident observations by incident type.",
		},
		[]string{
			"incident_type",
		},
	)

	// evidenceCollectionFailuresTotal counts failures while collecting
	// supplemental evidence.
	//
	// evidence_type must remain low-cardinality:
	// pod
	// event
	// log
	evidenceCollectionFailuresTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "kubetriage",
			Subsystem: "evidence",
			Name:      "collection_failures_total",
			Help:      "Total number of supplemental evidence collection failures.",
		},
		[]string{
			"evidence_type",
		},
	)

	// incidentReportTransitionsTotal counts important IncidentReport lifecycle
	// transitions.
	//
	// transition is bounded:
	// created
	// resolved
	incidentReportTransitionsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "kubetriage",
			Subsystem: "incident_report",
			Name:      "transitions_total",
			Help:      "Total number of IncidentReport lifecycle transitions.",
		},
		[]string{
			"transition",
		},
	)
)

func init() {
	crmetrics.Registry.MustRegister(
		reconcileTotal,
		reconcileDuration,
		incidentsDetectedTotal,
		evidenceCollectionFailuresTotal,
		incidentReportTransitionsTotal,
	)
}

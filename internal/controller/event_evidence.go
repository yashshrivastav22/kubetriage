package controller

import (
	"context"
	"sort"

	opsv1alpha1 "github.com/yashshrivastav22/kubetriage/api/v1alpha1"

	eventsv1 "k8s.io/api/events/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	maxIncidentEvents         = 10
	maxIncidentEventNoteRunes = 1024
)

// collectPodEventEvidence collects a bounded set of Kubernetes Events that
// belong to the exact Pod instance identified by podUID.
func (r *IncidentPolicyReconciler) collectPodEventEvidence(
	ctx context.Context,
	namespace string,
	podUID string,
) ([]opsv1alpha1.IncidentEventEvidence, error) {
	eventList := &eventsv1.EventList{}

	if err := r.List(
		ctx,
		eventList,
		client.InNamespace(namespace),
	); err != nil {
		return nil, err
	}

	matchingEvents := make(
		[]eventsv1.Event,
		0,
	)

	for i := range eventList.Items {
		event := &eventList.Items[i]

		// Match the exact Pod instance, not merely the Pod name.
		//
		// A deleted/recreated Pod may reuse a name but always receives a
		// different UID.
		if event.Regarding.UID != types.UID(podUID) {
			continue
		}

		matchingEvents = append(
			matchingEvents,
			*event,
		)
	}

	// Newest evidence first.
	sort.SliceStable(
		matchingEvents,
		func(i int, j int) bool {
			left := eventLastObservedTime(
				&matchingEvents[i],
			)

			right := eventLastObservedTime(
				&matchingEvents[j],
			)

			return left.Time.After(
				right.Time,
			)
		},
	)

	if len(matchingEvents) > maxIncidentEvents {
		matchingEvents =
			matchingEvents[:maxIncidentEvents]
	}

	evidence := make(
		[]opsv1alpha1.IncidentEventEvidence,
		0,
		len(matchingEvents),
	)

	for i := range matchingEvents {
		event := &matchingEvents[i]

		firstObserved :=
			metav1.NewTime(
				event.EventTime.Time,
			)

		lastObserved :=
			firstObserved

		count :=
			int32(1)

		if event.Series != nil {
			count =
				event.Series.Count

			lastObserved =
				metav1.NewTime(
					event.Series.LastObservedTime.Time,
				)
		}

		evidence = append(
			evidence,
			opsv1alpha1.IncidentEventEvidence{
				Type: event.Type,

				Reason: event.Reason,

				Action: event.Action,

				// Security boundary:
				// Kubernetes Event notes are untrusted workload/runtime
				// text. Redact likely secrets before storing them.
				Note: sanitizeAndTruncateEvidence(
					event.Note,
					maxIncidentEventNoteRunes,
				),

				Count: count,

				FirstObservedAt: &firstObserved,

				LastObservedAt: &lastObserved,

				ReportingController: event.ReportingController,
			},
		)
	}

	return evidence, nil
}

func eventLastObservedTime(
	event *eventsv1.Event,
) metav1.Time {
	if event.Series != nil {
		return metav1.NewTime(
			event.Series.LastObservedTime.Time,
		)
	}

	return metav1.NewTime(
		event.EventTime.Time,
	)
}

// truncateRunes truncates text by Unicode code points rather than bytes.
//
// Kubernetes CRD MaxLength validation is character-oriented, and evidence may
// contain multi-byte UTF-8 characters.
func truncateRunes(
	value string,
	limit int,
) string {
	if limit <= 0 {
		return ""
	}

	runes :=
		[]rune(value)

	if len(runes) <= limit {
		return value
	}

	return string(
		runes[:limit],
	)
}

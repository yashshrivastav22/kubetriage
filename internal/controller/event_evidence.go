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

// collectPodEventEvidence collects a bounded set of Kubernetes Events
// associated with one Pod.
//
// Events are supplemental evidence. They are not used to decide whether
// an incident exists.
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

	// Match by Pod UID rather than Pod name.
	//
	// Pod names can theoretically be reused, but UID identifies the exact
	// Pod instance involved in this incident.
	for i := range eventList.Items {
		event := &eventList.Items[i]

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
			left :=
				eventLastObservedTime(
					&matchingEvents[i],
				)

			right :=
				eventLastObservedTime(
					&matchingEvents[j],
				)

			return left.Time.After(right.Time)
		},
	)

	// Keep IncidentReport bounded.
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

		count := int32(1)

		// EventSeries represents a repeating Event.
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

				Note: truncateRunes(
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

// eventLastObservedTime returns the best available timestamp for sorting
// Events from newest to oldest.
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

// truncateRunes limits human-readable Event notes without splitting
// multi-byte UTF-8 characters.
func truncateRunes(
	value string,
	limit int,
) string {
	runes := []rune(value)

	if len(runes) <= limit {
		return value
	}

	return string(
		runes[:limit],
	)
}

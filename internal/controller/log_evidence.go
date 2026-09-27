package controller

import (
	"context"
	"errors"
	"fmt"

	opsv1alpha1 "github.com/yashshrivastav22/kubetriage/api/v1alpha1"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// collectContainerLogEvidence collects bounded current and previous logs for
// the affected container.
//
// Logs are supplemental evidence. Failure to collect them must never prevent
// KubeTriage from recording the primary incident.
func (r *IncidentPolicyReconciler) collectContainerLogEvidence(
	ctx context.Context,
	namespace string,
	finding *incidentFinding,
) (opsv1alpha1.IncidentLogEvidence, error) {
	if r.LogReader == nil {
		return opsv1alpha1.IncidentLogEvidence{}, nil
	}

	now := metav1.Now()

	evidence := opsv1alpha1.IncidentLogEvidence{
		CollectedAt: &now,
	}

	var collectionErrors []error
	anySuccessfulRead := false

	// Request one byte beyond our storage limit.
	//
	// This gives boundLogBytes an opportunity to determine whether the
	// locally stored excerpt had to be truncated.
	requestLimit := incidentLogLimitBytes + 1

	// ---------------------------------------------------------------------
	// Current container logs.
	// ---------------------------------------------------------------------

	currentData, err := r.LogReader.ReadContainerLogs(
		ctx,
		namespace,
		finding.PodName,
		finding.ContainerName,
		false,
		incidentLogTailLines,
		requestLimit,
	)

	if err != nil {
		collectionErrors = append(
			collectionErrors,
			fmt.Errorf(
				"read current logs for pod %s container %s: %w",
				finding.PodName,
				finding.ContainerName,
				err,
			),
		)
	} else {
		current, truncated := boundLogBytes(
			currentData,
			int(incidentLogLimitBytes),
		)

		evidence.Current = current
		evidence.CurrentTruncated = truncated
		anySuccessfulRead = true
	}

	// ---------------------------------------------------------------------
	// Previous container logs.
	//
	// Previous logs are useful only when Kubernetes indicates that the
	// container has restarted or has a previous termination.
	// ---------------------------------------------------------------------

	shouldCollectPrevious :=
		finding.RestartCount > 0 ||
			finding.LastTerminationReason != ""

	if shouldCollectPrevious {
		previousData, previousErr :=
			r.LogReader.ReadContainerLogs(
				ctx,
				namespace,
				finding.PodName,
				finding.ContainerName,
				true,
				incidentLogTailLines,
				requestLimit,
			)

		if previousErr != nil {
			collectionErrors = append(
				collectionErrors,
				fmt.Errorf(
					"read previous logs for pod %s container %s: %w",
					finding.PodName,
					finding.ContainerName,
					previousErr,
				),
			)
		} else {
			previous, truncated := boundLogBytes(
				previousData,
				int(incidentLogLimitBytes),
			)

			evidence.Previous = previous
			evidence.PreviousTruncated = truncated
			anySuccessfulRead = true
		}
	}

	// If every attempted read failed, return zero evidence. The caller can
	// preserve any previously collected log evidence.
	if !anySuccessfulRead && len(collectionErrors) > 0 {
		return opsv1alpha1.IncidentLogEvidence{},
			errors.Join(collectionErrors...)
	}

	return evidence, errors.Join(collectionErrors...)
}

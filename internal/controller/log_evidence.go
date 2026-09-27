package controller

import (
	"context"
	"errors"
	"fmt"
	"strings"

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

	now :=
		metav1.Now()

	evidence :=
		opsv1alpha1.IncidentLogEvidence{
			CollectedAt: &now,
		}

	var collectionErrors []error

	anySuccessfulRead :=
		false

	// Request one byte beyond the final storage limit.
	//
	// This allows KubeTriage to tell whether the stored excerpt had to be
	// truncated.
	requestLimit :=
		incidentLogLimitBytes + 1

	// ---------------------------------------------------------------------
	// Current container logs.
	// ---------------------------------------------------------------------

	currentData, err :=
		r.LogReader.ReadContainerLogs(
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
		current, truncated :=
			sanitizeBoundedLogBytes(
				currentData,
				int(incidentLogLimitBytes),
			)

		evidence.Current =
			current

		evidence.CurrentTruncated =
			truncated

		anySuccessfulRead =
			true
	}

	// ---------------------------------------------------------------------
	// Previous container logs.
	//
	// Previous logs are useful when Kubernetes reports evidence that this
	// container has restarted or previously terminated.
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
			previous, truncated :=
				sanitizeBoundedLogBytes(
					previousData,
					int(incidentLogLimitBytes),
				)

			evidence.Previous =
				previous

			evidence.PreviousTruncated =
				truncated

			anySuccessfulRead =
				true
		}
	}

	// Every requested log operation failed.
	//
	// Return zero evidence so the caller can preserve an older successful
	// collection rather than overwriting it.
	if !anySuccessfulRead &&
		len(collectionErrors) > 0 {

		return opsv1alpha1.IncidentLogEvidence{},
			errors.Join(collectionErrors...)
	}

	// Partial success returns both useful evidence and an error so the caller
	// can record an evidence-collection failure metric without discarding the
	// successful portion.
	return evidence,
		errors.Join(collectionErrors...)
}

// sanitizeBoundedLogBytes creates the final safe log representation stored in
// IncidentReport.status.
//
// Ordering matters:
//
//	raw Kubernetes logs
//	        ↓
//	make UTF-8 safe
//	        ↓
//	redact likely secrets
//	        ↓
//	enforce final byte limit
//
// Sanitization occurs before the final size bound so credentials near the
// boundary cannot escape redaction merely because truncation split a pattern.
func sanitizeBoundedLogBytes(
	data []byte,
	limit int,
) (string, bool) {
	if limit <= 0 {
		return "", len(data) > 0
	}

	// Pod logs should normally be UTF-8 text, but the storage boundary should
	// not trust that assumption. Invalid sequences are removed.
	validText :=
		strings.ToValidUTF8(
			string(data),
			"",
		)

	sanitized :=
		sanitizeEvidenceText(
			validText,
		)

	bounded, sanitizedTruncated :=
		boundLogBytes(
			[]byte(sanitized),
			limit,
		)

	// Preserve the fact that the original response exceeded our storage
	// boundary even if redaction later shortened the text.
	sourceTruncated :=
		len(data) > limit

	return bounded,
		sourceTruncated || sanitizedTruncated
}

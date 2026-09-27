package controller

import (
	"context"
	"fmt"

	opsv1alpha1 "github.com/yashshrivastav22/kubetriage/api/v1alpha1"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

const maxTerminationMessageRunes = 1024

// collectPodContainerEvidence gathers bounded structured evidence from the
// exact Pod/container associated with an incident.
func (r *IncidentPolicyReconciler) collectPodContainerEvidence(
	ctx context.Context,
	namespace string,
	finding *incidentFinding,
) (opsv1alpha1.IncidentEvidence, error) {
	// Detector-derived evidence is populated first.
	//
	// If richer Pod evidence cannot be collected, these facts remain
	// available to the IncidentReport.
	evidence := opsv1alpha1.IncidentEvidence{
		RestartCount: finding.RestartCount,

		CurrentState: finding.CurrentState,

		WaitingReason: finding.WaitingReason,

		LastTerminationReason: finding.LastTerminationReason,

		ExitCode: finding.ExitCode,
	}

	pod :=
		&corev1.Pod{}

	if err := r.Get(
		ctx,
		types.NamespacedName{
			Name: finding.PodName,

			Namespace: namespace,
		},
		pod,
	); err != nil {
		return evidence, err
	}

	// Never attach evidence from a replacement Pod that happens to have the
	// same name.
	if string(pod.UID) != finding.PodUID {
		return evidence, fmt.Errorf(
			"pod UID changed while collecting evidence for %s: expected %s, got %s",
			finding.PodName,
			finding.PodUID,
			string(pod.UID),
		)
	}

	evidence.NodeName =
		pod.Spec.NodeName

	evidence.ConfiguredImage =
		configuredImageForContainer(
			pod,
			finding.ContainerName,
		)

	containerStatus :=
		findContainerStatus(
			pod,
			finding.ContainerName,
		)

	if containerStatus == nil {
		return evidence, nil
	}

	evidence.RestartCount =
		containerStatus.RestartCount

	evidence.RuntimeImage =
		containerStatus.Image

	evidence.ImageID =
		containerStatus.ImageID

	evidence.ContainerID =
		containerStatus.ContainerID

	evidence.CurrentState =
		containerStateName(
			containerStatus.State,
		)

	if containerStatus.State.Waiting != nil {
		evidence.WaitingReason =
			containerStatus.State.Waiting.Reason
	}

	termination :=
		containerStatus.State.Terminated

	if termination == nil {
		termination =
			containerStatus.LastTerminationState.Terminated
	}

	if termination != nil {
		populateTerminationEvidence(
			&evidence,
			termination,
		)
	}

	return evidence, nil
}

func configuredImageForContainer(
	pod *corev1.Pod,
	containerName string,
) string {
	for i := range pod.Spec.InitContainers {
		container :=
			&pod.Spec.InitContainers[i]

		if container.Name == containerName {
			return container.Image
		}
	}

	for i := range pod.Spec.Containers {
		container :=
			&pod.Spec.Containers[i]

		if container.Name == containerName {
			return container.Image
		}
	}

	return ""
}

func findContainerStatus(
	pod *corev1.Pod,
	containerName string,
) *corev1.ContainerStatus {
	for i := range pod.Status.InitContainerStatuses {
		containerStatus :=
			&pod.Status.InitContainerStatuses[i]

		if containerStatus.Name == containerName {
			return containerStatus
		}
	}

	for i := range pod.Status.ContainerStatuses {
		containerStatus :=
			&pod.Status.ContainerStatuses[i]

		if containerStatus.Name == containerName {
			return containerStatus
		}
	}

	return nil
}

func populateTerminationEvidence(
	evidence *opsv1alpha1.IncidentEvidence,
	termination *corev1.ContainerStateTerminated,
) {
	if termination == nil {
		return
	}

	evidence.LastTerminationReason =
		termination.Reason

	exitCode :=
		termination.ExitCode

	evidence.ExitCode =
		&exitCode

	if termination.Signal != 0 {
		signal :=
			termination.Signal

		evidence.Signal =
			&signal
	}

	if !termination.StartedAt.IsZero() {
		startedAt :=
			metav1.NewTime(
				termination.StartedAt.Time,
			)

		evidence.TerminationStartedAt =
			&startedAt
	}

	if !termination.FinishedAt.IsZero() {
		finishedAt :=
			metav1.NewTime(
				termination.FinishedAt.Time,
			)

		evidence.TerminationFinishedAt =
			&finishedAt
	}

	// Security boundary:
	//
	// Container termination messages can contain application-generated text,
	// including credentials or connection strings. Redact before persistence.
	evidence.TerminationMessage =
		sanitizeAndTruncateEvidence(
			termination.Message,
			maxTerminationMessageRunes,
		)

	// Prefer the ID of the terminated container instance when available.
	if termination.ContainerID != "" {
		evidence.ContainerID =
			termination.ContainerID
	}
}

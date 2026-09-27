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

// collectPodContainerEvidence collects structured Pod and container evidence
// for one detected incident.
//
// The incident itself is still determined by the detector. This function only
// enriches the IncidentReport with additional diagnostic context.
func (r *IncidentPolicyReconciler) collectPodContainerEvidence(
	ctx context.Context,
	namespace string,
	finding *incidentFinding,
) (opsv1alpha1.IncidentEvidence, error) {
	// Start with evidence already discovered by the detector.
	evidence := opsv1alpha1.IncidentEvidence{
		RestartCount:          finding.RestartCount,
		CurrentState:          finding.CurrentState,
		WaitingReason:         finding.WaitingReason,
		LastTerminationReason: finding.LastTerminationReason,
		ExitCode:              finding.ExitCode,
	}

	pod := &corev1.Pod{}

	if err := r.Get(
		ctx,
		types.NamespacedName{
			Name:      finding.PodName,
			Namespace: namespace,
		},
		pod,
	); err != nil {
		return evidence, err
	}

	// Defensive identity check.
	//
	// Pod names can be reused, so the UID must match the Pod that originally
	// generated this incident finding.
	if string(pod.UID) != finding.PodUID {
		return evidence, fmt.Errorf(
			"pod UID changed while collecting evidence for %s: expected %s, got %s",
			finding.PodName,
			finding.PodUID,
			string(pod.UID),
		)
	}

	// ---------------------------------------------------------------------
	// Pod-level evidence.
	// ---------------------------------------------------------------------

	evidence.NodeName = pod.Spec.NodeName

	// ---------------------------------------------------------------------
	// Configured container image from PodSpec.
	// ---------------------------------------------------------------------

	evidence.ConfiguredImage = configuredImageForContainer(
		pod,
		finding.ContainerName,
	)

	// ---------------------------------------------------------------------
	// Runtime container information from ContainerStatus.
	// ---------------------------------------------------------------------

	containerStatus := findContainerStatus(
		pod,
		finding.ContainerName,
	)

	if containerStatus == nil {
		return evidence, nil
	}

	evidence.RestartCount = containerStatus.RestartCount
	evidence.RuntimeImage = containerStatus.Image
	evidence.ImageID = containerStatus.ImageID
	evidence.ContainerID = containerStatus.ContainerID
	evidence.CurrentState = containerStateName(
		containerStatus.State,
	)

	// Preserve the waiting reason when the container is currently waiting.
	if containerStatus.State.Waiting != nil {
		evidence.WaitingReason =
			containerStatus.State.Waiting.Reason
	}

	// ---------------------------------------------------------------------
	// Termination evidence.
	//
	// First prefer the current terminated state.
	//
	// If the container has already restarted, use LastTerminationState.
	// This is especially important for OOMKilled because the current
	// container may already be Running while the previous instance was
	// terminated by the kernel.
	// ---------------------------------------------------------------------

	termination := containerStatus.State.Terminated

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

// configuredImageForContainer finds the image originally configured in the
// Pod specification.
//
// We inspect both init containers and regular containers because KubeTriage
// detects failures in both groups.
func configuredImageForContainer(
	pod *corev1.Pod,
	containerName string,
) string {
	for i := range pod.Spec.InitContainers {
		container := &pod.Spec.InitContainers[i]

		if container.Name == containerName {
			return container.Image
		}
	}

	for i := range pod.Spec.Containers {
		container := &pod.Spec.Containers[i]

		if container.Name == containerName {
			return container.Image
		}
	}

	return ""
}

// findContainerStatus returns the ContainerStatus matching the affected
// container.
//
// Both init and regular container statuses are supported.
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

// populateTerminationEvidence copies bounded termination information from
// Kubernetes into the IncidentReport evidence model.
func populateTerminationEvidence(
	evidence *opsv1alpha1.IncidentEvidence,
	termination *corev1.ContainerStateTerminated,
) {
	if termination == nil {
		return
	}

	evidence.LastTerminationReason =
		termination.Reason

	exitCode := termination.ExitCode
	evidence.ExitCode = &exitCode

	// A signal value of zero means no signal was reported.
	if termination.Signal != 0 {
		signal := termination.Signal
		evidence.Signal = &signal
	}

	if !termination.StartedAt.IsZero() {
		startedAt := metav1.NewTime(
			termination.StartedAt.Time,
		)

		evidence.TerminationStartedAt =
			&startedAt
	}

	if !termination.FinishedAt.IsZero() {
		finishedAt := metav1.NewTime(
			termination.FinishedAt.Time,
		)

		evidence.TerminationFinishedAt =
			&finishedAt
	}

	evidence.TerminationMessage =
		truncateRunes(
			termination.Message,
			maxTerminationMessageRunes,
		)

	// If Kubernetes provides the ID of the terminated container, prefer it
	// because it identifies the exact failed container instance.
	if termination.ContainerID != "" {
		evidence.ContainerID =
			termination.ContainerID
	}
}

/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

// IncidentEventEvidence represents bounded Kubernetes Event evidence collected
// for the Pod involved in an incident.
type IncidentEventEvidence struct {
	// Type is normally Normal or Warning.
	// +optional
	Type string `json:"type,omitempty"`

	// Reason is the machine-readable Kubernetes Event reason.
	// +optional
	Reason string `json:"reason,omitempty"`

	// Action describes the action reported by the Event producer.
	// +optional
	Action string `json:"action,omitempty"`

	// Note contains the human-readable Event description.
	//
	// KubeTriage bounds this field before storing it.
	// +kubebuilder:validation:MaxLength=1024
	// +optional
	Note string `json:"note,omitempty"`

	// Count represents how many times this Event occurred.
	// +optional
	Count int32 `json:"count,omitempty"`

	// FirstObservedAt represents when the Event was first observed.
	// +optional
	FirstObservedAt *metav1.Time `json:"firstObservedAt,omitempty"`

	// LastObservedAt represents the most recent observation of the Event.
	// +optional
	LastObservedAt *metav1.Time `json:"lastObservedAt,omitempty"`

	// ReportingController identifies the component that reported the Event.
	// +optional
	ReportingController string `json:"reportingController,omitempty"`
}

// IncidentEvidence contains bounded Kubernetes evidence associated with an
// incident.
type IncidentEvidence struct {
	// NodeName is the Kubernetes node assigned to the affected Pod.
	// +optional
	NodeName string `json:"nodeName,omitempty"`

	// ConfiguredImage is the image declared in the Pod specification.
	//
	// Example:
	// checkout:v2.4.1
	// +optional
	ConfiguredImage string `json:"configuredImage,omitempty"`

	// RuntimeImage is the image name reported by ContainerStatus.
	//
	// This can differ from the value originally declared in the Pod spec.
	// +optional
	RuntimeImage string `json:"runtimeImage,omitempty"`

	// ImageID identifies the exact image reported by the container runtime.
	// +optional
	ImageID string `json:"imageID,omitempty"`

	// ContainerID identifies the running or terminated container instance.
	//
	// Example:
	// containerd://abc123
	// +optional
	ContainerID string `json:"containerID,omitempty"`

	// RestartCount is the restart count reported for the affected container.
	// +optional
	RestartCount int32 `json:"restartCount,omitempty"`

	// CurrentState describes the current container state.
	//
	// Expected values include:
	// Waiting
	// Running
	// Terminated
	// Unknown
	// +optional
	CurrentState string `json:"currentState,omitempty"`

	// WaitingReason contains the Kubernetes waiting reason when applicable.
	//
	// Examples:
	// CrashLoopBackOff
	// ErrImagePull
	// ImagePullBackOff
	// +optional
	WaitingReason string `json:"waitingReason,omitempty"`

	// LastTerminationReason contains the termination reason when available.
	//
	// Example:
	// OOMKilled
	// +optional
	LastTerminationReason string `json:"lastTerminationReason,omitempty"`

	// ExitCode contains the container termination exit code when available.
	// +optional
	ExitCode *int32 `json:"exitCode,omitempty"`

	// Signal contains the signal associated with container termination when
	// Kubernetes reports one.
	// +optional
	Signal *int32 `json:"signal,omitempty"`

	// TerminationStartedAt is when the terminated container execution began.
	// +optional
	TerminationStartedAt *metav1.Time `json:"terminationStartedAt,omitempty"`

	// TerminationFinishedAt is when the container terminated.
	// +optional
	TerminationFinishedAt *metav1.Time `json:"terminationFinishedAt,omitempty"`

	// TerminationMessage contains bounded termination information reported by
	// Kubernetes.
	//
	// +kubebuilder:validation:MaxLength=1024
	// +optional
	TerminationMessage string `json:"terminationMessage,omitempty"`

	// Events contains a bounded set of Kubernetes Events related to the
	// affected Pod.
	//
	// +kubebuilder:validation:MaxItems=10
	// +listType=atomic
	// +optional
	Events []IncidentEventEvidence `json:"events,omitempty"`
}

// IncidentReportSpec defines the stable identity of a detected incident.
type IncidentReportSpec struct {
	// PolicyName is the IncidentPolicy that detected this incident.
	// +kubebuilder:validation:MinLength=1
	// +required
	PolicyName string `json:"policyName"`

	// PolicyUID uniquely identifies the IncidentPolicy instance.
	// +kubebuilder:validation:MinLength=1
	// +required
	PolicyUID string `json:"policyUID"`

	// PodName is the affected Pod.
	// +kubebuilder:validation:MinLength=1
	// +required
	PodName string `json:"podName"`

	// PodUID uniquely identifies the affected Pod instance.
	// +kubebuilder:validation:MinLength=1
	// +required
	PodUID string `json:"podUID"`

	// ContainerName is the affected container.
	// +kubebuilder:validation:MinLength=1
	// +required
	ContainerName string `json:"containerName"`

	// IncidentType identifies the Kubernetes failure detected.
	//
	// +kubebuilder:validation:Enum=CrashLoopBackOff;OOMKilled;ErrImagePull;ImagePullBackOff
	// +required
	IncidentType string `json:"incidentType"`

	// Fingerprint is the stable identity used to prevent duplicate reports.
	//
	// Derived from:
	// Policy UID
	// Pod UID
	// Container name
	// Incident type
	//
	// +kubebuilder:validation:MinLength=1
	// +required
	Fingerprint string `json:"fingerprint"`
}

// IncidentReportStatus defines the observed lifecycle of an incident.
type IncidentReportStatus struct {
	// Phase describes the current incident lifecycle state.
	//
	// +kubebuilder:validation:Enum=Active;Resolved
	// +optional
	Phase string `json:"phase,omitempty"`

	// FirstDetectedAt is when KubeTriage first observed this incident.
	// +optional
	FirstDetectedAt *metav1.Time `json:"firstDetectedAt,omitempty"`

	// LastObservedAt is the most recent time KubeTriage observed the incident.
	// +optional
	LastObservedAt *metav1.Time `json:"lastObservedAt,omitempty"`

	// ResolvedAt is populated when the incident is no longer observed.
	// +optional
	ResolvedAt *metav1.Time `json:"resolvedAt,omitempty"`

	// Evidence contains bounded Kubernetes evidence associated with the
	// incident.
	// +optional
	Evidence IncidentEvidence `json:"evidence,omitempty"`

	// Conditions represent additional lifecycle state.
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Type",type=string,JSONPath=`.spec.incidentType`
// +kubebuilder:printcolumn:name="Pod",type=string,JSONPath=`.spec.podName`
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.phase`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// IncidentReport is the Schema for the incidentreports API.
type IncidentReport struct {
	metav1.TypeMeta `json:",inline"`

	metav1.ObjectMeta `json:"metadata,omitzero"`

	// spec defines the stable identity of the incident.
	// +required
	Spec IncidentReportSpec `json:"spec"`

	// status defines lifecycle and evidence.
	// +optional
	Status IncidentReportStatus `json:"status,omitzero"`
}

// +kubebuilder:object:root=true

// IncidentReportList contains a list of IncidentReport.
type IncidentReportList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`

	Items []IncidentReport `json:"items"`
}

func init() {
	SchemeBuilder.Register(func(s *runtime.Scheme) error {
		s.AddKnownTypes(
			SchemeGroupVersion,
			&IncidentReport{},
			&IncidentReportList{},
		)

		return nil
	})
}

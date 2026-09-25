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

// IncidentEvidence contains bounded Kubernetes evidence associated with
// an incident.
type IncidentEvidence struct {
	// RestartCount is the restart count reported for the affected container.
	// +optional
	RestartCount int32 `json:"restartCount,omitempty"`

	// CurrentState describes the current container state when the incident
	// was last evaluated.
	// +optional
	CurrentState string `json:"currentState,omitempty"`

	// WaitingReason contains the Kubernetes waiting reason when applicable.
	// Examples include CrashLoopBackOff and ImagePullBackOff.
	// +optional
	WaitingReason string `json:"waitingReason,omitempty"`

	// LastTerminationReason contains the previous container termination reason
	// when available.
	// Example: OOMKilled.
	// +optional
	LastTerminationReason string `json:"lastTerminationReason,omitempty"`

	// ExitCode contains the previous container exit code when available.
	// +optional
	ExitCode *int32 `json:"exitCode,omitempty"`
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

	// Fingerprint is the stable identity used by KubeTriage to avoid creating
	// duplicate reports for the same incident.
	//
	// It will be derived from the policy, Pod, container, and incident type.
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

	// LastObservedAt is the most recent time KubeTriage observed the
	// incident condition.
	// +optional
	LastObservedAt *metav1.Time `json:"lastObservedAt,omitempty"`

	// ResolvedAt is populated when the incident is no longer observed.
	// +optional
	ResolvedAt *metav1.Time `json:"resolvedAt,omitempty"`

	// Evidence contains bounded Kubernetes evidence associated with
	// the most recent observation.
	// +optional
	Evidence IncidentEvidence `json:"evidence,omitempty"`

	// Conditions represent additional lifecycle state for this report.
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

	// status defines the observed lifecycle and evidence for the incident.
	// +optional
	Status IncidentReportStatus `json:"status,omitzero"`
}

// +kubebuilder:object:root=true

// IncidentReportList contains a list of IncidentReport.
type IncidentReportList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`
	Items           []IncidentReport `json:"items"`
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

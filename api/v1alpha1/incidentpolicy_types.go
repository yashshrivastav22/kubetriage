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

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// IncidentChecks defines which incident conditions KubeTriage should detect.
type IncidentChecks struct {
	// CrashLoop enables detection of containers in CrashLoopBackOff.
	// +kubebuilder:default=false
	// +optional
	CrashLoop bool `json:"crashLoop,omitempty"`

	// OOMKilled enables detection of containers terminated because of OOMKilled.
	// +kubebuilder:default=false
	// +optional
	OOMKilled bool `json:"oomKilled,omitempty"`

	// ImagePull enables detection of image pull failures such as
	// ImagePullBackOff and ErrImagePull.
	// +kubebuilder:default=false
	// +optional
	ImagePull bool `json:"imagePull,omitempty"`
}

// IncidentPolicySpec defines the desired state of IncidentPolicy.
type IncidentPolicySpec struct {
	// Selector identifies Pods monitored by this policy.
	// The selector applies only within the IncidentPolicy's namespace.
	//
	// +kubebuilder:validation:XValidation:rule="(has(self.matchLabels) && size(self.matchLabels) > 0) || (has(self.matchExpressions) && size(self.matchExpressions) > 0)",message="selector must contain at least one matchLabels or matchExpressions entry"
	// +required
	Selector metav1.LabelSelector `json:"selector"`

	// Checks specifies which incident conditions should be detected.
	//
	// +kubebuilder:validation:XValidation:rule="self.crashLoop || self.oomKilled || self.imagePull",message="at least one incident check must be enabled"
	// +required
	Checks IncidentChecks `json:"checks"`
}

// IncidentPolicyStatus defines the observed state of IncidentPolicy.
type IncidentPolicyStatus struct {
	// ObservedGeneration is the latest generation processed by the controller.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// MonitoredPods is the number of Pods matching this policy.
	// +optional
	MonitoredPods int32 `json:"monitoredPods,omitempty"`

	// Conditions represent the current state of the IncidentPolicy.
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status

// IncidentPolicy is the Schema for the incidentpolicies API
type IncidentPolicy struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is a standard object metadata
	// +optional
	metav1.ObjectMeta `json:"metadata,omitzero"`

	// spec defines the desired state of IncidentPolicy
	// +required
	Spec IncidentPolicySpec `json:"spec"`

	// status defines the observed state of IncidentPolicy
	// +optional
	Status IncidentPolicyStatus `json:"status,omitzero"`
}

// +kubebuilder:object:root=true

// IncidentPolicyList contains a list of IncidentPolicy
type IncidentPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`
	Items           []IncidentPolicy `json:"items"`
}

func init() {
	SchemeBuilder.Register(func(s *runtime.Scheme) error {
		s.AddKnownTypes(SchemeGroupVersion, &IncidentPolicy{}, &IncidentPolicyList{})
		return nil
	})
}

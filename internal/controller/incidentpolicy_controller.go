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

package controller

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"time"

	opsv1alpha1 "github.com/yashshrivastav22/kubetriage/api/v1alpha1"

	corev1 "k8s.io/api/core/v1"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

const (
	conditionTypeReady            = "Ready"
	conditionTypeIncidentDetected = "IncidentDetected"
)

type crashLoopFinding struct {
	Pod       string
	Container string
}

// IncidentPolicyReconciler reconciles an IncidentPolicy object.
type IncidentPolicyReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=ops.kubetriage.dev,resources=incidentpolicies,verbs=get;list;watch
// +kubebuilder:rbac:groups=ops.kubetriage.dev,resources=incidentpolicies/status,verbs=get;update;patch
// +kubebuilder:rbac:groups="",resources=pods,verbs=get;list;watch

func (r *IncidentPolicyReconciler) Reconcile(
	ctx context.Context,
	req ctrl.Request,
) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	// ---------------------------------------------------------------------
	// STEP 1: Retrieve the IncidentPolicy.
	// ---------------------------------------------------------------------

	policy := &opsv1alpha1.IncidentPolicy{}

	if err := r.Get(ctx, req.NamespacedName, policy); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// Keep the original object so we can avoid unnecessary status writes.
	before := policy.DeepCopy()

	policy.Status.ObservedGeneration = policy.Generation

	// ---------------------------------------------------------------------
	// STEP 2: Convert the Kubernetes LabelSelector.
	// ---------------------------------------------------------------------

	selector, err := metav1.LabelSelectorAsSelector(
		&policy.Spec.Selector,
	)

	if err != nil {
		policy.Status.MonitoredPods = 0

		apimeta.SetStatusCondition(
			&policy.Status.Conditions,
			metav1.Condition{
				Type:               conditionTypeReady,
				Status:             metav1.ConditionFalse,
				ObservedGeneration: policy.Generation,
				Reason:             "InvalidSelector",
				Message:            err.Error(),
			},
		)

		apimeta.SetStatusCondition(
			&policy.Status.Conditions,
			metav1.Condition{
				Type:               conditionTypeIncidentDetected,
				Status:             metav1.ConditionUnknown,
				ObservedGeneration: policy.Generation,
				Reason:             "EvaluationFailed",
				Message:            "Incident evaluation could not be completed.",
			},
		)

		if err := r.updateStatusIfChanged(ctx, before, policy); err != nil {
			return ctrl.Result{}, err
		}

		return ctrl.Result{}, nil
	}

	// ---------------------------------------------------------------------
	// STEP 3: Find Pods matching the IncidentPolicy.
	// ---------------------------------------------------------------------

	pods := &corev1.PodList{}

	if err := r.List(
		ctx,
		pods,
		client.InNamespace(policy.Namespace),
		client.MatchingLabelsSelector{
			Selector: selector,
		},
	); err != nil {
		return ctrl.Result{}, err
	}

	policy.Status.MonitoredPods = int32(len(pods.Items))

	log.Info(
		"evaluating IncidentPolicy",
		"policy",
		policy.Name,
		"namespace",
		policy.Namespace,
		"matchingPods",
		len(pods.Items),
	)

	// ---------------------------------------------------------------------
	// STEP 4: Handle a selector that currently matches no Pods.
	// ---------------------------------------------------------------------

	if len(pods.Items) == 0 {
		apimeta.SetStatusCondition(
			&policy.Status.Conditions,
			metav1.Condition{
				Type:               conditionTypeReady,
				Status:             metav1.ConditionFalse,
				ObservedGeneration: policy.Generation,
				Reason:             "NoMatchingPods",
				Message:            "The policy selector currently matches no Pods.",
			},
		)

		apimeta.SetStatusCondition(
			&policy.Status.Conditions,
			metav1.Condition{
				Type:               conditionTypeIncidentDetected,
				Status:             metav1.ConditionUnknown,
				ObservedGeneration: policy.Generation,
				Reason:             "NoMatchingPods",
				Message:            "Incident state cannot be determined because no Pods match the selector.",
			},
		)

		if err := r.updateStatusIfChanged(ctx, before, policy); err != nil {
			return ctrl.Result{}, err
		}

		return ctrl.Result{
			RequeueAfter: 30 * time.Second,
		}, nil
	}

	// ---------------------------------------------------------------------
	// STEP 5: Track checks that exist in the API but are not implemented yet.
	// ---------------------------------------------------------------------

	var unsupportedChecks []string

	if policy.Spec.Checks.OOMKilled {
		unsupportedChecks = append(
			unsupportedChecks,
			"oomKilled",
		)
	}

	if policy.Spec.Checks.ImagePull {
		unsupportedChecks = append(
			unsupportedChecks,
			"imagePull",
		)
	}

	if len(unsupportedChecks) > 0 {
		apimeta.SetStatusCondition(
			&policy.Status.Conditions,
			metav1.Condition{
				Type:               conditionTypeReady,
				Status:             metav1.ConditionFalse,
				ObservedGeneration: policy.Generation,
				Reason:             "UnsupportedChecks",
				Message: fmt.Sprintf(
					"Checks not implemented yet: %s",
					strings.Join(unsupportedChecks, ", "),
				),
			},
		)
	} else {
		apimeta.SetStatusCondition(
			&policy.Status.Conditions,
			metav1.Condition{
				Type:               conditionTypeReady,
				Status:             metav1.ConditionTrue,
				ObservedGeneration: policy.Generation,
				Reason:             "EvaluationReady",
				Message:            "All configured incident checks can be evaluated.",
			},
		)
	}

	// ---------------------------------------------------------------------
	// STEP 6: Detect CrashLoopBackOff.
	// ---------------------------------------------------------------------

	var finding *crashLoopFinding

	if policy.Spec.Checks.CrashLoop {
		finding = findCrashLoopBackOff(pods.Items)
	}

	switch {
	case finding != nil:
		apimeta.SetStatusCondition(
			&policy.Status.Conditions,
			metav1.Condition{
				Type:               conditionTypeIncidentDetected,
				Status:             metav1.ConditionTrue,
				ObservedGeneration: policy.Generation,
				Reason:             "CrashLoopBackOffDetected",
				Message: fmt.Sprintf(
					"Pod %s container %s is in CrashLoopBackOff.",
					finding.Pod,
					finding.Container,
				),
			},
		)

	case len(unsupportedChecks) > 0:
		// We cannot claim NoIncident because some requested checks
		// have not been implemented yet.
		apimeta.SetStatusCondition(
			&policy.Status.Conditions,
			metav1.Condition{
				Type:               conditionTypeIncidentDetected,
				Status:             metav1.ConditionUnknown,
				ObservedGeneration: policy.Generation,
				Reason:             "PartialEvaluation",
				Message:            "No CrashLoopBackOff was detected, but one or more configured checks are not implemented yet.",
			},
		)

	default:
		apimeta.SetStatusCondition(
			&policy.Status.Conditions,
			metav1.Condition{
				Type:               conditionTypeIncidentDetected,
				Status:             metav1.ConditionFalse,
				ObservedGeneration: policy.Generation,
				Reason:             "NoIncidentDetected",
				Message:            "No configured incident condition was detected.",
			},
		)
	}

	// ---------------------------------------------------------------------
	// STEP 7: Update status only when something actually changed.
	// ---------------------------------------------------------------------

	if err := r.updateStatusIfChanged(
		ctx,
		before,
		policy,
	); err != nil {
		return ctrl.Result{}, err
	}

	// ---------------------------------------------------------------------
	// STEP 8: Periodic reconciliation fallback.
	// ---------------------------------------------------------------------

	return ctrl.Result{
		RequeueAfter: 30 * time.Second,
	}, nil
}

// findCrashLoopBackOff searches all matching Pods for CrashLoopBackOff.
//
// We inspect both regular containers and init containers.
func findCrashLoopBackOff(
	pods []corev1.Pod,
) *crashLoopFinding {
	for i := range pods {
		pod := &pods[i]

		statusGroups := [][]corev1.ContainerStatus{
			pod.Status.InitContainerStatuses,
			pod.Status.ContainerStatuses,
		}

		for _, statuses := range statusGroups {
			for _, containerStatus := range statuses {
				waiting := containerStatus.State.Waiting

				if waiting == nil {
					continue
				}

				if waiting.Reason == "CrashLoopBackOff" {
					return &crashLoopFinding{
						Pod:       pod.Name,
						Container: containerStatus.Name,
					}
				}
			}
		}
	}

	return nil
}

// updateStatusIfChanged prevents unnecessary writes to the Kubernetes API.
func (r *IncidentPolicyReconciler) updateStatusIfChanged(
	ctx context.Context,
	before *opsv1alpha1.IncidentPolicy,
	after *opsv1alpha1.IncidentPolicy,
) error {
	if reflect.DeepEqual(
		before.Status,
		after.Status,
	) {
		return nil
	}

	return r.Status().Patch(
		ctx,
		after,
		client.MergeFrom(before),
	)
}

// SetupWithManager registers IncidentPolicy as the primary resource watched
// by this controller.
//
// Pod watches will be added in the next development phase.
func (r *IncidentPolicyReconciler) SetupWithManager(
	mgr ctrl.Manager,
) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&opsv1alpha1.IncidentPolicy{}).
		Named("incidentpolicy").
		Complete(r)
}

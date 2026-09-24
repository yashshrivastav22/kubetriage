package controller

import (
	"context"
	"fmt"
	"reflect"
	"time"

	opsv1alpha1 "github.com/yashshrivastav22/kubetriage/api/v1alpha1"

	corev1 "k8s.io/api/core/v1"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"

	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

const (
	conditionTypeReady            = "Ready"
	conditionTypeIncidentDetected = "IncidentDetected"
)

// incidentFinding represents one detected incident condition.
type incidentFinding struct {
	Pod       string
	Container string
	Reason    string
	Message   string
}

// IncidentPolicyReconciler reconciles an IncidentPolicy object.
type IncidentPolicyReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// -----------------------------------------------------------------------------
// RBAC
//
// KubeTriage can:
// - read IncidentPolicies
// - update IncidentPolicy status
// - read/watch Pods
//
// KubeTriage cannot modify monitored Pods.
// -----------------------------------------------------------------------------

// +kubebuilder:rbac:groups=ops.kubetriage.dev,resources=incidentpolicies,verbs=get;list;watch
// +kubebuilder:rbac:groups=ops.kubetriage.dev,resources=incidentpolicies/status,verbs=get;update;patch
// +kubebuilder:rbac:groups="",resources=pods,verbs=get;list;watch

// Reconcile evaluates the IncidentPolicy against Pods matching its selector.
func (r *IncidentPolicyReconciler) Reconcile(
	ctx context.Context,
	req ctrl.Request,
) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	// ---------------------------------------------------------------------
	// STEP 1:
	// Retrieve the IncidentPolicy.
	// ---------------------------------------------------------------------

	policy := &opsv1alpha1.IncidentPolicy{}

	if err := r.Get(
		ctx,
		req.NamespacedName,
		policy,
	); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// Save the original object so we can avoid unnecessary status writes.
	before := policy.DeepCopy()

	policy.Status.ObservedGeneration = policy.Generation

	// ---------------------------------------------------------------------
	// STEP 2:
	// Convert the Kubernetes LabelSelector into a selector that can be used
	// when listing Pods.
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

		if err := r.updateStatusIfChanged(
			ctx,
			before,
			policy,
		); err != nil {
			return ctrl.Result{}, err
		}

		return ctrl.Result{}, nil
	}

	// ---------------------------------------------------------------------
	// STEP 3:
	// Find Pods in the same namespace that match the policy selector.
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

	policy.Status.MonitoredPods = int32(
		len(pods.Items),
	)

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
	// STEP 4:
	// If no Pods match, KubeTriage cannot determine application health.
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

		if err := r.updateStatusIfChanged(
			ctx,
			before,
			policy,
		); err != nil {
			return ctrl.Result{}, err
		}

		return ctrl.Result{
			RequeueAfter: 30 * time.Second,
		}, nil
	}

	// ---------------------------------------------------------------------
	// STEP 5:
	// All V1 checks are currently implemented.
	// ---------------------------------------------------------------------

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

	// ---------------------------------------------------------------------
	// STEP 6:
	// Run the configured detectors.
	//
	// Current priority:
	//
	// 1. CrashLoopBackOff
	// 2. OOMKilled
	// 3. Image pull failures
	//
	// For now, KubeTriage reports the first finding.
	// Later IncidentReport support will allow multiple simultaneous findings.
	// ---------------------------------------------------------------------

	var finding *incidentFinding

	if policy.Spec.Checks.CrashLoop {
		finding = findCrashLoopBackOff(
			pods.Items,
		)
	}

	if finding == nil &&
		policy.Spec.Checks.OOMKilled {
		finding = findOOMKilled(
			pods.Items,
		)
	}

	if finding == nil &&
		policy.Spec.Checks.ImagePull {
		finding = findImagePullFailure(
			pods.Items,
		)
	}

	// ---------------------------------------------------------------------
	// STEP 7:
	// Publish the result.
	// ---------------------------------------------------------------------

	if finding != nil {
		apimeta.SetStatusCondition(
			&policy.Status.Conditions,
			metav1.Condition{
				Type:               conditionTypeIncidentDetected,
				Status:             metav1.ConditionTrue,
				ObservedGeneration: policy.Generation,
				Reason:             finding.Reason + "Detected",
				Message:            finding.Message,
			},
		)
	} else {
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
	// STEP 8:
	// Update status only when the status actually changed.
	// ---------------------------------------------------------------------

	if err := r.updateStatusIfChanged(
		ctx,
		before,
		policy,
	); err != nil {
		return ctrl.Result{}, err
	}

	// ---------------------------------------------------------------------
	// STEP 9:
	// Periodic fallback reconciliation.
	//
	// Pod watches provide event-driven reconciliation, but this periodic
	// reconciliation gives us an additional eventual-consistency mechanism.
	// ---------------------------------------------------------------------

	return ctrl.Result{
		RequeueAfter: 30 * time.Second,
	}, nil
}

// -----------------------------------------------------------------------------
// CrashLoopBackOff detector
// -----------------------------------------------------------------------------

// findCrashLoopBackOff searches regular containers and init containers for
// the CrashLoopBackOff waiting reason.
func findCrashLoopBackOff(
	pods []corev1.Pod,
) *incidentFinding {
	for i := range pods {
		pod := &pods[i]

		statusGroups := [][]corev1.ContainerStatus{
			pod.Status.InitContainerStatuses,
			pod.Status.ContainerStatuses,
		}

		for _, statuses := range statusGroups {
			for _, containerStatus := range statuses {
				waiting :=
					containerStatus.State.Waiting

				if waiting == nil {
					continue
				}

				if waiting.Reason != "CrashLoopBackOff" {
					continue
				}

				return &incidentFinding{
					Pod:       pod.Name,
					Container: containerStatus.Name,
					Reason:    "CrashLoopBackOff",
					Message: fmt.Sprintf(
						"Pod %s container %s is in CrashLoopBackOff.",
						pod.Name,
						containerStatus.Name,
					),
				}
			}
		}
	}

	return nil
}

// -----------------------------------------------------------------------------
// OOMKilled detector
// -----------------------------------------------------------------------------

// findOOMKilled searches regular containers and init containers for an
// OOMKilled termination.
//
// Kubernetes may restart the container after the OOM event, so we inspect
// both the current terminated state and LastTerminationState.
func findOOMKilled(
	pods []corev1.Pod,
) *incidentFinding {
	for i := range pods {
		pod := &pods[i]

		statusGroups := [][]corev1.ContainerStatus{
			pod.Status.InitContainerStatuses,
			pod.Status.ContainerStatuses,
		}

		for _, statuses := range statusGroups {
			for _, containerStatus := range statuses {
				currentTermination :=
					containerStatus.State.Terminated

				if currentTermination != nil &&
					currentTermination.Reason == "OOMKilled" {
					return newOOMKilledFinding(
						pod.Name,
						containerStatus.Name,
					)
				}

				lastTermination :=
					containerStatus.LastTerminationState.Terminated

				if lastTermination != nil &&
					lastTermination.Reason == "OOMKilled" {
					return newOOMKilledFinding(
						pod.Name,
						containerStatus.Name,
					)
				}
			}
		}
	}

	return nil
}

// newOOMKilledFinding creates the normalized finding returned by the
// OOMKilled detector.
func newOOMKilledFinding(
	podName string,
	containerName string,
) *incidentFinding {
	return &incidentFinding{
		Pod:       podName,
		Container: containerName,
		Reason:    "OOMKilled",
		Message: fmt.Sprintf(
			"Pod %s container %s was terminated with reason OOMKilled.",
			podName,
			containerName,
		),
	}
}

// -----------------------------------------------------------------------------
// Image pull detector
// -----------------------------------------------------------------------------

// findImagePullFailure detects image-pull failures reported through the
// container waiting state.
//
// Kubernetes commonly reports:
//
// - ErrImagePull
// - ImagePullBackOff
func findImagePullFailure(
	pods []corev1.Pod,
) *incidentFinding {
	for i := range pods {
		pod := &pods[i]

		statusGroups := [][]corev1.ContainerStatus{
			pod.Status.InitContainerStatuses,
			pod.Status.ContainerStatuses,
		}

		for _, statuses := range statusGroups {
			for _, containerStatus := range statuses {
				waiting :=
					containerStatus.State.Waiting

				if waiting == nil {
					continue
				}

				switch waiting.Reason {
				case "ErrImagePull",
					"ImagePullBackOff":

					return &incidentFinding{
						Pod:       pod.Name,
						Container: containerStatus.Name,
						Reason:    waiting.Reason,
						Message: fmt.Sprintf(
							"Pod %s container %s cannot pull its image: %s.",
							pod.Name,
							containerStatus.Name,
							waiting.Reason,
						),
					}
				}
			}
		}
	}

	return nil
}

// -----------------------------------------------------------------------------
// Status update helper
// -----------------------------------------------------------------------------

// updateStatusIfChanged prevents unnecessary writes to the Kubernetes API.
//
// Reconciliation can happen repeatedly, so we avoid patching status when the
// calculated status already matches what Kubernetes stores.
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

// -----------------------------------------------------------------------------
// Pod event mapping
// -----------------------------------------------------------------------------

// mapPodToIncidentPolicies maps a Pod event to all IncidentPolicies in the
// same namespace whose selector matches that Pod.
//
// IncidentPolicy remains the primary resource reconciled by this controller.
// Pods are secondary watched resources.
func (r *IncidentPolicyReconciler) mapPodToIncidentPolicies(
	ctx context.Context,
	obj client.Object,
) []reconcile.Request {
	log := logf.FromContext(ctx)

	pod, ok := obj.(*corev1.Pod)

	if !ok {
		return nil
	}

	policies := &opsv1alpha1.IncidentPolicyList{}

	if err := r.List(
		ctx,
		policies,
		client.InNamespace(
			pod.Namespace,
		),
	); err != nil {
		log.Error(
			err,
			"failed to list IncidentPolicies for Pod event",
			"pod",
			pod.Name,
			"namespace",
			pod.Namespace,
		)

		return nil
	}

	requests := make(
		[]reconcile.Request,
		0,
	)

	for i := range policies.Items {
		policy := &policies.Items[i]

		selector, err :=
			metav1.LabelSelectorAsSelector(
				&policy.Spec.Selector,
			)

		if err != nil {
			log.Error(
				err,
				"failed to convert IncidentPolicy selector",
				"policy",
				policy.Name,
				"namespace",
				policy.Namespace,
			)

			continue
		}

		if !selector.Matches(
			labels.Set(pod.Labels),
		) {
			continue
		}

		requests = append(
			requests,
			reconcile.Request{
				NamespacedName: types.NamespacedName{
					Name:      policy.Name,
					Namespace: policy.Namespace,
				},
			},
		)
	}

	return requests
}

// -----------------------------------------------------------------------------
// Controller registration
// -----------------------------------------------------------------------------

// SetupWithManager registers:
//
// IncidentPolicy
//
//	Primary watched resource.
//
// Pod
//
//	Secondary watched resource.
//
// When a Pod changes, mapPodToIncidentPolicies determines which policies need
// to be reconciled.
func (r *IncidentPolicyReconciler) SetupWithManager(
	mgr ctrl.Manager,
) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(
			&opsv1alpha1.IncidentPolicy{},
		).
		Watches(
			&corev1.Pod{},
			handler.EnqueueRequestsFromMapFunc(
				r.mapPodToIncidentPolicies,
			),
		).
		Named(
			"incidentpolicy",
		).
		Complete(r)
}

package controller

import (
	"context"
	"crypto/sha256"
	"fmt"
	"reflect"
	"time"

	opsv1alpha1 "github.com/yashshrivastav22/kubetriage/api/v1alpha1"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
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

	reportPolicyUIDLabel    = "ops.kubetriage.dev/policy-uid"
	reportIncidentTypeLabel = "ops.kubetriage.dev/incident-type"
)

// incidentFinding represents a normalized incident detected from Pod status.
type incidentFinding struct {
	PodName       string
	PodUID        string
	ContainerName string
	IncidentType  string
	Message       string

	RestartCount          int32
	CurrentState          string
	WaitingReason         string
	LastTerminationReason string
	ExitCode              *int32
}

// IncidentPolicyReconciler reconciles an IncidentPolicy object.
type IncidentPolicyReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// -----------------------------------------------------------------------------
// RBAC
// -----------------------------------------------------------------------------

// +kubebuilder:rbac:groups=ops.kubetriage.dev,resources=incidentpolicies,verbs=get;list;watch
// +kubebuilder:rbac:groups=ops.kubetriage.dev,resources=incidentpolicies/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=ops.kubetriage.dev,resources=incidentreports,verbs=get;list;watch;create
// +kubebuilder:rbac:groups=ops.kubetriage.dev,resources=incidentreports/status,verbs=get;update;patch
// +kubebuilder:rbac:groups="",resources=pods,verbs=get;list;watch

func (r *IncidentPolicyReconciler) Reconcile(
	ctx context.Context,
	req ctrl.Request,
) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	// ---------------------------------------------------------------------
	// STEP 1: Retrieve IncidentPolicy.
	// ---------------------------------------------------------------------

	policy := &opsv1alpha1.IncidentPolicy{}

	if err := r.Get(
		ctx,
		req.NamespacedName,
		policy,
	); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	before := policy.DeepCopy()

	policy.Status.ObservedGeneration = policy.Generation

	// ---------------------------------------------------------------------
	// STEP 2: Convert label selector.
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

		if err := r.updatePolicyStatusIfChanged(
			ctx,
			before,
			policy,
		); err != nil {
			return ctrl.Result{}, err
		}

		return ctrl.Result{}, nil
	}

	// ---------------------------------------------------------------------
	// STEP 3: Find matching Pods.
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
	// STEP 4: No matching Pods.
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

		if err := r.updatePolicyStatusIfChanged(
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
	// STEP 5: Policy can be evaluated.
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
	// STEP 6: Run detectors.
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
	// STEP 7: If an incident exists, create or update its IncidentReport.
	// ---------------------------------------------------------------------

	if finding != nil {
		if err := r.ensureIncidentReport(
			ctx,
			policy,
			finding,
		); err != nil {
			return ctrl.Result{}, err
		}

		apimeta.SetStatusCondition(
			&policy.Status.Conditions,
			metav1.Condition{
				Type:               conditionTypeIncidentDetected,
				Status:             metav1.ConditionTrue,
				ObservedGeneration: policy.Generation,
				Reason:             finding.IncidentType + "Detected",
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
	// STEP 8: Persist IncidentPolicy status.
	// ---------------------------------------------------------------------

	if err := r.updatePolicyStatusIfChanged(
		ctx,
		before,
		policy,
	); err != nil {
		return ctrl.Result{}, err
	}

	// ---------------------------------------------------------------------
	// STEP 9: Periodic fallback reconciliation.
	// ---------------------------------------------------------------------

	return ctrl.Result{
		RequeueAfter: 30 * time.Second,
	}, nil
}

// -----------------------------------------------------------------------------
// CrashLoopBackOff detector
// -----------------------------------------------------------------------------

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

				if waiting == nil ||
					waiting.Reason != "CrashLoopBackOff" {
					continue
				}

				return &incidentFinding{
					PodName:       pod.Name,
					PodUID:        string(pod.UID),
					ContainerName: containerStatus.Name,
					IncidentType:  "CrashLoopBackOff",

					Message: fmt.Sprintf(
						"Pod %s container %s is in CrashLoopBackOff.",
						pod.Name,
						containerStatus.Name,
					),

					RestartCount:  containerStatus.RestartCount,
					CurrentState:  "Waiting",
					WaitingReason: waiting.Reason,
				}
			}
		}
	}

	return nil
}

// -----------------------------------------------------------------------------
// OOMKilled detector
// -----------------------------------------------------------------------------

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
						pod,
						containerStatus,
						currentTermination,
					)
				}

				lastTermination :=
					containerStatus.LastTerminationState.Terminated

				if lastTermination != nil &&
					lastTermination.Reason == "OOMKilled" {
					return newOOMKilledFinding(
						pod,
						containerStatus,
						lastTermination,
					)
				}
			}
		}
	}

	return nil
}

func newOOMKilledFinding(
	pod *corev1.Pod,
	containerStatus corev1.ContainerStatus,
	termination *corev1.ContainerStateTerminated,
) *incidentFinding {
	exitCode := termination.ExitCode

	return &incidentFinding{
		PodName:       pod.Name,
		PodUID:        string(pod.UID),
		ContainerName: containerStatus.Name,
		IncidentType:  "OOMKilled",

		Message: fmt.Sprintf(
			"Pod %s container %s was terminated with reason OOMKilled.",
			pod.Name,
			containerStatus.Name,
		),

		RestartCount: containerStatus.RestartCount,

		CurrentState: containerStateName(
			containerStatus.State,
		),

		LastTerminationReason: "OOMKilled",
		ExitCode:              &exitCode,
	}
}

// -----------------------------------------------------------------------------
// Image pull detector
// -----------------------------------------------------------------------------

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
						PodName:       pod.Name,
						PodUID:        string(pod.UID),
						ContainerName: containerStatus.Name,
						IncidentType:  waiting.Reason,

						Message: fmt.Sprintf(
							"Pod %s container %s cannot pull its image: %s.",
							pod.Name,
							containerStatus.Name,
							waiting.Reason,
						),

						RestartCount:  containerStatus.RestartCount,
						CurrentState:  "Waiting",
						WaitingReason: waiting.Reason,
					}
				}
			}
		}
	}

	return nil
}

// -----------------------------------------------------------------------------
// IncidentReport lifecycle
// -----------------------------------------------------------------------------

func (r *IncidentPolicyReconciler) ensureIncidentReport(
	ctx context.Context,
	policy *opsv1alpha1.IncidentPolicy,
	finding *incidentFinding,
) error {
	fingerprint := buildIncidentFingerprint(
		policy,
		finding,
	)

	reportName := incidentReportName(
		fingerprint,
	)

	key := types.NamespacedName{
		Name:      reportName,
		Namespace: policy.Namespace,
	}

	report := &opsv1alpha1.IncidentReport{}

	err := r.Get(
		ctx,
		key,
		report,
	)

	if apierrors.IsNotFound(err) {
		report = &opsv1alpha1.IncidentReport{
			ObjectMeta: metav1.ObjectMeta{
				Name:      reportName,
				Namespace: policy.Namespace,

				Labels: map[string]string{
					reportPolicyUIDLabel: string(policy.UID),

					reportIncidentTypeLabel: finding.IncidentType,
				},
			},

			Spec: opsv1alpha1.IncidentReportSpec{
				PolicyName:    policy.Name,
				PolicyUID:     string(policy.UID),
				PodName:       finding.PodName,
				PodUID:        finding.PodUID,
				ContainerName: finding.ContainerName,
				IncidentType:  finding.IncidentType,
				Fingerprint:   fingerprint,
			},
		}

		if err := r.Create(
			ctx,
			report,
		); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}

	// Defensive collision check.
	if report.Spec.Fingerprint != fingerprint {
		return fmt.Errorf(
			"incident report name collision: report %s has unexpected fingerprint",
			report.Name,
		)
	}

	return r.updateIncidentReportStatus(
		ctx,
		report,
		finding,
	)
}

func (r *IncidentPolicyReconciler) updateIncidentReportStatus(
	ctx context.Context,
	report *opsv1alpha1.IncidentReport,
	finding *incidentFinding,
) error {
	before := report.DeepCopy()

	now := metav1.Now()

	if report.Status.FirstDetectedAt == nil {
		firstDetected := now
		report.Status.FirstDetectedAt = &firstDetected
	}

	lastObserved := now
	report.Status.LastObservedAt = &lastObserved

	report.Status.Phase = "Active"
	report.Status.ResolvedAt = nil

	report.Status.Evidence =
		opsv1alpha1.IncidentEvidence{
			RestartCount:          finding.RestartCount,
			CurrentState:          finding.CurrentState,
			WaitingReason:         finding.WaitingReason,
			LastTerminationReason: finding.LastTerminationReason,
			ExitCode:              finding.ExitCode,
		}

	if reflect.DeepEqual(
		before.Status,
		report.Status,
	) {
		return nil
	}

	return r.Status().Patch(
		ctx,
		report,
		client.MergeFrom(before),
	)
}

// buildIncidentFingerprint creates a deterministic identity from:
//
// Policy UID + Pod UID + Container + Incident Type.
//
// Repeated reconciliation of the same incident therefore produces the same
// fingerprint.
func buildIncidentFingerprint(
	policy *opsv1alpha1.IncidentPolicy,
	finding *incidentFinding,
) string {
	raw := fmt.Sprintf(
		"%s|%s|%s|%s",
		string(policy.UID),
		finding.PodUID,
		finding.ContainerName,
		finding.IncidentType,
	)

	hash := sha256.Sum256(
		[]byte(raw),
	)

	return fmt.Sprintf(
		"%x",
		hash,
	)
}

// incidentReportName converts the fingerprint into a short deterministic
// Kubernetes resource name.
func incidentReportName(
	fingerprint string,
) string {
	const fingerprintLength = 16

	short := fingerprint

	if len(short) > fingerprintLength {
		short = short[:fingerprintLength]
	}

	return "incident-" + short
}

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

func containerStateName(
	state corev1.ContainerState,
) string {
	switch {
	case state.Waiting != nil:
		return "Waiting"

	case state.Running != nil:
		return "Running"

	case state.Terminated != nil:
		return "Terminated"

	default:
		return "Unknown"
	}
}

func (r *IncidentPolicyReconciler) updatePolicyStatusIfChanged(
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

func (r *IncidentPolicyReconciler) mapPodToIncidentPolicies(
	ctx context.Context,
	obj client.Object,
) []reconcile.Request {
	log := logf.FromContext(ctx)

	pod, ok := obj.(*corev1.Pod)

	if !ok {
		return nil
	}

	policies :=
		&opsv1alpha1.IncidentPolicyList{}

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

	requests :=
		make([]reconcile.Request, 0)

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
			labels.Set(
				pod.Labels,
			),
		) {
			continue
		}

		requests = append(
			requests,
			reconcile.Request{
				NamespacedName: types.NamespacedName{
					Name: policy.Name,

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

func (r *IncidentPolicyReconciler) SetupWithManager(
	mgr ctrl.Manager,
) error {
	return ctrl.NewControllerManagedBy(
		mgr,
	).
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

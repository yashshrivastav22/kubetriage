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

// incidentFinding represents one normalized incident detected from Pod status.
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
// +kubebuilder:rbac:groups=events.k8s.io,resources=events,verbs=get;list;watch

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
	// STEP 2: Convert the label selector.
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
	// STEP 3: Find every Pod matching this IncidentPolicy.
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
	//
	// We intentionally DO NOT resolve existing reports here.
	//
	// No matching Pods means the application state is unknown. It does not
	// prove that an existing incident has recovered.
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
	// STEP 5: The policy can be evaluated.
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
	// Run ALL enabled detectors.
	//
	// Previously KubeTriage returned only one *incidentFinding.
	//
	// Now every detector can return multiple findings.
	// ---------------------------------------------------------------------

	findings := make(
		[]incidentFinding,
		0,
	)

	if policy.Spec.Checks.CrashLoop {
		findings = append(
			findings,
			findCrashLoopBackOff(
				pods.Items,
			)...,
		)
	}

	if policy.Spec.Checks.OOMKilled {
		findings = append(
			findings,
			findOOMKilled(
				pods.Items,
			)...,
		)
	}

	if policy.Spec.Checks.ImagePull {
		findings = append(
			findings,
			findImagePullFailures(
				pods.Items,
			)...,
		)
	}

	// ---------------------------------------------------------------------
	// STEP 7:
	// Create/update every currently observed incident.
	//
	// observedFingerprints represents the incident state of the cluster
	// during THIS reconciliation.
	// ---------------------------------------------------------------------

	observedFingerprints :=
		make(map[string]struct{})

	activeFindings :=
		make([]incidentFinding, 0)

	for i := range findings {
		finding := &findings[i]

		fingerprint := buildIncidentFingerprint(
			policy,
			finding,
		)

		// Defensive de-duplication.
		//
		// If two detector paths somehow produce the exact same incident,
		// process it only once during this reconciliation.
		if _, alreadyObserved :=
			observedFingerprints[fingerprint]; alreadyObserved {
			continue
		}

		if err := r.ensureIncidentReport(
			ctx,
			policy,
			finding,
			fingerprint,
		); err != nil {
			return ctrl.Result{}, err
		}

		observedFingerprints[fingerprint] =
			struct{}{}

		activeFindings = append(
			activeFindings,
			*finding,
		)
	}

	// ---------------------------------------------------------------------
	// STEP 8:
	// Resolve only reports that were NOT observed during this reconciliation.
	//
	// This is what allows independent incident lifecycle management.
	// ---------------------------------------------------------------------

	if err := r.resolveUnobservedIncidentReports(
		ctx,
		policy,
		observedFingerprints,
	); err != nil {
		return ctrl.Result{}, err
	}

	// ---------------------------------------------------------------------
	// STEP 9:
	// Publish summary state on IncidentPolicy.
	//
	// IncidentPolicy is the summary.
	// IncidentReport objects hold the detailed per-incident state.
	// ---------------------------------------------------------------------

	switch len(activeFindings) {
	case 0:
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

	case 1:
		finding := activeFindings[0]

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

	default:
		apimeta.SetStatusCondition(
			&policy.Status.Conditions,
			metav1.Condition{
				Type:               conditionTypeIncidentDetected,
				Status:             metav1.ConditionTrue,
				ObservedGeneration: policy.Generation,
				Reason:             "MultipleIncidentsDetected",
				Message: fmt.Sprintf(
					"%d active incidents were detected across matching Pods.",
					len(activeFindings),
				),
			},
		)
	}

	// ---------------------------------------------------------------------
	// STEP 10: Persist IncidentPolicy status.
	// ---------------------------------------------------------------------

	if err := r.updatePolicyStatusIfChanged(
		ctx,
		before,
		policy,
	); err != nil {
		return ctrl.Result{}, err
	}

	// ---------------------------------------------------------------------
	// STEP 11: Periodic reconciliation fallback.
	// ---------------------------------------------------------------------

	return ctrl.Result{
		RequeueAfter: 30 * time.Second,
	}, nil
}

// -----------------------------------------------------------------------------
// CrashLoopBackOff detector
// -----------------------------------------------------------------------------

// findCrashLoopBackOff returns every CrashLoopBackOff currently visible in
// the selected Pods.
func findCrashLoopBackOff(
	pods []corev1.Pod,
) []incidentFinding {
	findings := make(
		[]incidentFinding,
		0,
	)

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

				findings = append(
					findings,
					incidentFinding{
						PodName:       pod.Name,
						PodUID:        string(pod.UID),
						ContainerName: containerStatus.Name,
						IncidentType:  "CrashLoopBackOff",

						Message: fmt.Sprintf(
							"Pod %s container %s is in CrashLoopBackOff.",
							pod.Name,
							containerStatus.Name,
						),

						RestartCount: containerStatus.RestartCount,

						CurrentState: "Waiting",

						WaitingReason: waiting.Reason,
					},
				)
			}
		}
	}

	return findings
}

// -----------------------------------------------------------------------------
// OOMKilled detector
// -----------------------------------------------------------------------------

// findOOMKilled returns every currently observable OOMKilled incident.
func findOOMKilled(
	pods []corev1.Pod,
) []incidentFinding {
	findings := make(
		[]incidentFinding,
		0,
	)

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
					findings = append(
						findings,
						newOOMKilledFinding(
							pod,
							containerStatus,
							currentTermination,
						),
					)

					// Avoid creating the same OOM finding twice if both
					// current and previous termination states happen to
					// contain OOMKilled.
					continue
				}

				lastTermination :=
					containerStatus.LastTerminationState.Terminated

				if lastTermination != nil &&
					lastTermination.Reason == "OOMKilled" {
					findings = append(
						findings,
						newOOMKilledFinding(
							pod,
							containerStatus,
							lastTermination,
						),
					)
				}
			}
		}
	}

	return findings
}

func newOOMKilledFinding(
	pod *corev1.Pod,
	containerStatus corev1.ContainerStatus,
	termination *corev1.ContainerStateTerminated,
) incidentFinding {
	exitCode := termination.ExitCode

	return incidentFinding{
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

		ExitCode: &exitCode,
	}
}

// -----------------------------------------------------------------------------
// Image pull detector
// -----------------------------------------------------------------------------

// findImagePullFailures returns every ErrImagePull or ImagePullBackOff
// currently visible in the selected Pods.
func findImagePullFailures(
	pods []corev1.Pod,
) []incidentFinding {
	findings := make(
		[]incidentFinding,
		0,
	)

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

					findings = append(
						findings,
						incidentFinding{
							PodName: pod.Name,

							PodUID: string(pod.UID),

							ContainerName: containerStatus.Name,

							IncidentType: waiting.Reason,

							Message: fmt.Sprintf(
								"Pod %s container %s cannot pull its image: %s.",
								pod.Name,
								containerStatus.Name,
								waiting.Reason,
							),

							RestartCount: containerStatus.RestartCount,

							CurrentState: "Waiting",

							WaitingReason: waiting.Reason,
						},
					)
				}
			}
		}
	}

	return findings
}

// -----------------------------------------------------------------------------
// IncidentReport create/update lifecycle
// -----------------------------------------------------------------------------

func (r *IncidentPolicyReconciler) ensureIncidentReport(
	ctx context.Context,
	policy *opsv1alpha1.IncidentPolicy,
	finding *incidentFinding,
	fingerprint string,
) error {
	reportName := incidentReportName(
		fingerprint,
	)

	key := types.NamespacedName{
		Name:      reportName,
		Namespace: policy.Namespace,
	}

	report :=
		&opsv1alpha1.IncidentReport{}

	err := r.Get(
		ctx,
		key,
		report,
	)

	if apierrors.IsNotFound(err) {
		report =
			&opsv1alpha1.IncidentReport{
				ObjectMeta: metav1.ObjectMeta{
					Name: reportName,

					Namespace: policy.Namespace,

					Labels: map[string]string{
						reportPolicyUIDLabel: string(policy.UID),

						reportIncidentTypeLabel: finding.IncidentType,
					},
				},

				Spec: opsv1alpha1.IncidentReportSpec{
					PolicyName: policy.Name,

					PolicyUID: string(policy.UID),

					PodName: finding.PodName,

					PodUID: finding.PodUID,

					ContainerName: finding.ContainerName,

					IncidentType: finding.IncidentType,

					Fingerprint: fingerprint,
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

	// Defensive fingerprint collision check.
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

// -----------------------------------------------------------------------------
// IncidentReport Active state
// -----------------------------------------------------------------------------

func (r *IncidentPolicyReconciler) updateIncidentReportStatus(
	ctx context.Context,
	report *opsv1alpha1.IncidentReport,
	finding *incidentFinding,
) error {
	log := logf.FromContext(ctx)

	before :=
		report.DeepCopy()

	now := metav1.Now()

	if report.Status.FirstDetectedAt == nil {
		firstDetected := now

		report.Status.FirstDetectedAt =
			&firstDetected
	}

	lastObserved := now

	report.Status.LastObservedAt =
		&lastObserved

	report.Status.Phase =
		"Active"

	report.Status.ResolvedAt =
		nil

	// -----------------------------------------------------------------
	// Collect Kubernetes Event evidence.
	//
	// Events are supplemental evidence, so an Event API failure should
	// not prevent the primary incident from being recorded.
	// -----------------------------------------------------------------

	eventEvidence, eventErr :=
		r.collectPodEventEvidence(
			ctx,
			report.Namespace,
			finding.PodUID,
		)

	if eventErr != nil {
		log.Error(
			eventErr,
			"failed to collect Kubernetes Event evidence",
			"incidentReport",
			report.Name,
			"pod",
			finding.PodName,
		)

		// Preserve previously collected Event evidence if this particular
		// Event lookup fails.
		eventEvidence =
			before.Status.Evidence.Events
	}

	report.Status.Evidence =
		opsv1alpha1.IncidentEvidence{
			RestartCount: finding.RestartCount,

			CurrentState: finding.CurrentState,

			WaitingReason: finding.WaitingReason,

			LastTerminationReason: finding.LastTerminationReason,

			ExitCode: finding.ExitCode,

			Events: eventEvidence,
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

// -----------------------------------------------------------------------------
// Independent IncidentReport resolution
// -----------------------------------------------------------------------------

// resolveUnobservedIncidentReports compares existing Active IncidentReports
// against the fingerprints that were actually observed during the current
// reconciliation.
//
// Observed report:
//     remains Active.
//
// Active report that was NOT observed:
//     becomes Resolved.

func (r *IncidentPolicyReconciler) resolveUnobservedIncidentReports(
	ctx context.Context,
	policy *opsv1alpha1.IncidentPolicy,
	observedFingerprints map[string]struct{},
) error {
	reports := &opsv1alpha1.IncidentReportList{}

	if err := r.List(
		ctx,
		reports,
		client.InNamespace(policy.Namespace),
		client.MatchingLabels{
			reportPolicyUIDLabel: string(policy.UID),
		},
	); err != nil {
		return err
	}

	now := metav1.Now()

	for i := range reports.Items {
		report := &reports.Items[i]

		// Only Active reports need lifecycle evaluation.
		if report.Status.Phase != "Active" {
			continue
		}

		// If this fingerprint was observed during the current
		// reconciliation, the incident still exists.
		if _, observed := observedFingerprints[report.Spec.Fingerprint]; observed {
			continue
		}

		// This report was Active previously but was not observed
		// during this reconciliation, so the incident has resolved.
		before := report.DeepCopy()

		report.Status.Phase = "Resolved"

		resolvedAt := now
		report.Status.ResolvedAt = &resolvedAt

		// Preserve historical information:
		//
		// FirstDetectedAt
		// LastObservedAt
		// Evidence

		if reflect.DeepEqual(
			before.Status,
			report.Status,
		) {
			continue
		}

		if err := r.Status().Patch(
			ctx,
			report,
			client.MergeFrom(before),
		); err != nil {
			return err
		}
	}

	return nil
}

// -----------------------------------------------------------------------------
// Incident fingerprint
// -----------------------------------------------------------------------------

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

	hash :=
		sha256.Sum256(
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
		short =
			short[:fingerprintLength]
	}

	return "incident-" + short
}

// -----------------------------------------------------------------------------
// Container state helper
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

// -----------------------------------------------------------------------------
// IncidentPolicy status helper
// -----------------------------------------------------------------------------

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
	log :=
		logf.FromContext(ctx)

	pod, ok :=
		obj.(*corev1.Pod)

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
		policy :=
			&policies.Items[i]

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

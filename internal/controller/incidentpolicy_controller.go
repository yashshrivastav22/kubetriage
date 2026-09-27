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

	reportPolicyUIDLabel = "ops.kubetriage.dev/policy-uid"

	reportIncidentTypeLabel = "ops.kubetriage.dev/incident-type"
)

// -----------------------------------------------------------------------------
// incidentFinding
//
// Internal normalized representation returned by the detection engine.
//
// Richer evidence is intentionally collected separately so detector logic stays
// deterministic and focused on identifying incident conditions.
// -----------------------------------------------------------------------------

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

// -----------------------------------------------------------------------------
// IncidentPolicyReconciler
// -----------------------------------------------------------------------------

type IncidentPolicyReconciler struct {
	client.Client

	Scheme *runtime.Scheme

	// LogReader abstracts access to the Kubernetes pods/log subresource.
	//
	// Production initializes the Kubernetes implementation in
	// SetupWithManager. Tests may inject a deterministic fake implementation.
	LogReader LogReader
}

// -----------------------------------------------------------------------------
// RBAC
// -----------------------------------------------------------------------------

// +kubebuilder:rbac:groups=ops.kubetriage.dev,resources=incidentpolicies,verbs=get;list;watch
// +kubebuilder:rbac:groups=ops.kubetriage.dev,resources=incidentpolicies/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=ops.kubetriage.dev,resources=incidentreports,verbs=get;list;watch;create
// +kubebuilder:rbac:groups=ops.kubetriage.dev,resources=incidentreports/status,verbs=get;update;patch
// +kubebuilder:rbac:groups="",resources=pods,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=pods/log,verbs=get
// +kubebuilder:rbac:groups=events.k8s.io,resources=events,verbs=get;list;watch

// -----------------------------------------------------------------------------
// Reconcile metrics wrapper
//
// All reconciliation paths flow through this wrapper so success/error counts
// and duration are recorded consistently.
// -----------------------------------------------------------------------------

func (r *IncidentPolicyReconciler) Reconcile(
	ctx context.Context,
	req ctrl.Request,
) (ctrl.Result, error) {
	startedAt := time.Now()

	result, err := r.reconcile(
		ctx,
		req,
	)

	reconcileDuration.Observe(
		time.Since(startedAt).Seconds(),
	)

	if err != nil {
		reconcileTotal.WithLabelValues(
			"error",
		).Inc()

		return result, err
	}

	reconcileTotal.WithLabelValues(
		"success",
	).Inc()

	return result, nil
}

// -----------------------------------------------------------------------------
// Core reconciliation
// -----------------------------------------------------------------------------

func (r *IncidentPolicyReconciler) reconcile(
	ctx context.Context,
	req ctrl.Request,
) (ctrl.Result, error) {
	policy :=
		&opsv1alpha1.IncidentPolicy{}

	// ---------------------------------------------------------------------
	// STEP 1:
	// Load the IncidentPolicy.
	//
	// NotFound is normal because an object may have been deleted after its
	// reconcile request was queued.
	// ---------------------------------------------------------------------

	if err := r.Get(
		ctx,
		req.NamespacedName,
		policy,
	); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}

		return ctrl.Result{}, fmt.Errorf(
			"get IncidentPolicy %s/%s: %w",
			req.Namespace,
			req.Name,
			err,
		)
	}

	before :=
		policy.DeepCopy()

	policy.Status.ObservedGeneration =
		policy.Generation

	// ---------------------------------------------------------------------
	// STEP 2:
	// Convert the Kubernetes LabelSelector.
	// ---------------------------------------------------------------------

	selector, err :=
		metav1.LabelSelectorAsSelector(
			&policy.Spec.Selector,
		)

	if err != nil {
		setPolicyCondition(
			policy,
			conditionTypeReady,
			metav1.ConditionFalse,
			"InvalidSelector",
			fmt.Sprintf(
				"IncidentPolicy selector could not be evaluated: %v",
				err,
			),
		)

		setPolicyCondition(
			policy,
			conditionTypeIncidentDetected,
			metav1.ConditionUnknown,
			"EvaluationFailed",
			"Incident detection could not run because the selector is invalid.",
		)

		if patchErr :=
			r.patchIncidentPolicyStatus(
				ctx,
				before,
				policy,
			); patchErr != nil {

			return ctrl.Result{}, patchErr
		}

		return ctrl.Result{}, fmt.Errorf(
			"convert IncidentPolicy selector: %w",
			err,
		)
	}

	// ---------------------------------------------------------------------
	// STEP 3:
	// Discover matching Pods in the same namespace.
	// ---------------------------------------------------------------------

	pods :=
		&corev1.PodList{}

	if err := r.List(
		ctx,
		pods,
		client.InNamespace(
			policy.Namespace,
		),
		client.MatchingLabelsSelector{
			Selector: selector,
		},
	); err != nil {
		return ctrl.Result{}, fmt.Errorf(
			"list Pods for IncidentPolicy %s/%s: %w",
			policy.Namespace,
			policy.Name,
			err,
		)
	}

	policy.Status.MonitoredPods =
		int32(len(pods.Items))

	// ---------------------------------------------------------------------
	// STEP 4:
	// No matching Pods.
	//
	// This is UNKNOWN incident state, not proof of recovery.
	//
	// We intentionally DO NOT resolve IncidentReports here because a missing
	// Pod may have been deleted/recreated, temporarily unavailable, or not yet
	// scheduled.
	// ---------------------------------------------------------------------

	if len(pods.Items) == 0 {
		setPolicyCondition(
			policy,
			conditionTypeReady,
			metav1.ConditionFalse,
			"NoMatchingPods",
			"No Pods currently match the IncidentPolicy selector.",
		)

		setPolicyCondition(
			policy,
			conditionTypeIncidentDetected,
			metav1.ConditionUnknown,
			"NoMatchingPods",
			"Incident state is unknown because no Pods currently match the selector.",
		)

		if err :=
			r.patchIncidentPolicyStatus(
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

	// Matching Pods exist, so evaluation can proceed.
	setPolicyCondition(
		policy,
		conditionTypeReady,
		metav1.ConditionTrue,
		"EvaluationReady",
		"Matching Pods are available for incident evaluation.",
	)

	// ---------------------------------------------------------------------
	// STEP 5:
	// Run every enabled detector.
	//
	// Detectors return ALL findings rather than only the first failure.
	// ---------------------------------------------------------------------

	findings :=
		make([]incidentFinding, 0)

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
	// STEP 6:
	// Build the currently observed incident set.
	// ---------------------------------------------------------------------

	observedFingerprints :=
		make(map[string]struct{})

	activeFindings :=
		make([]incidentFinding, 0)

	// ---------------------------------------------------------------------
	// STEP 7:
	// Create/update every currently observed incident.
	//
	// observedFingerprints represents the incident state of the cluster
	// during THIS reconciliation.
	// ---------------------------------------------------------------------

	for i := range findings {
		finding :=
			&findings[i]

		fingerprint :=
			buildIncidentFingerprint(
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

		if err :=
			r.ensureIncidentReport(
				ctx,
				policy,
				finding,
				fingerprint,
			); err != nil {

			return ctrl.Result{}, err
		}

		// -----------------------------------------------------------------
		// Phase 6.2C:
		// Incident observation metric.
		//
		// Increment only after the IncidentReport was successfully
		// processed.
		// -----------------------------------------------------------------

		incidentsDetectedTotal.WithLabelValues(
			finding.IncidentType,
		).Inc()

		observedFingerprints[fingerprint] =
			struct{}{}

		activeFindings = append(
			activeFindings,
			*finding,
		)
	}

	// ---------------------------------------------------------------------
	// STEP 8:
	// Resolve reports that were previously Active but are no longer observed.
	// ---------------------------------------------------------------------

	if err :=
		r.resolveUnobservedIncidentReports(
			ctx,
			policy,
			observedFingerprints,
		); err != nil {

		return ctrl.Result{}, err
	}

	// ---------------------------------------------------------------------
	// STEP 9:
	// Summarize active incidents on IncidentPolicy.status.
	//
	// IncidentPolicy is the current summary.
	// IncidentReport objects retain the detailed history.
	// ---------------------------------------------------------------------

	switch len(activeFindings) {
	case 0:
		setPolicyCondition(
			policy,
			conditionTypeIncidentDetected,
			metav1.ConditionFalse,
			"NoIncidentDetected",
			"No enabled incident checks are currently detecting an incident.",
		)

	case 1:
		finding :=
			activeFindings[0]

		setPolicyCondition(
			policy,
			conditionTypeIncidentDetected,
			metav1.ConditionTrue,
			finding.IncidentType+"Detected",
			finding.Message,
		)

	default:
		setPolicyCondition(
			policy,
			conditionTypeIncidentDetected,
			metav1.ConditionTrue,
			"MultipleIncidentsDetected",
			fmt.Sprintf(
				"%d active incidents were detected across matching Pods.",
				len(activeFindings),
			),
		)
	}

	// ---------------------------------------------------------------------
	// STEP 10:
	// Persist IncidentPolicy status only when it changed.
	// ---------------------------------------------------------------------

	if err :=
		r.patchIncidentPolicyStatus(
			ctx,
			before,
			policy,
		); err != nil {

		return ctrl.Result{}, err
	}

	// Event-driven Pod watches are the primary trigger.
	//
	// The periodic fallback ensures reconciliation still happens if an
	// external event is missed and also refreshes supplemental evidence.
	return ctrl.Result{
		RequeueAfter: 30 * time.Second,
	}, nil
}

// -----------------------------------------------------------------------------
// IncidentPolicy status helpers
// -----------------------------------------------------------------------------

func setPolicyCondition(
	policy *opsv1alpha1.IncidentPolicy,
	conditionType string,
	status metav1.ConditionStatus,
	reason string,
	message string,
) {
	apimeta.SetStatusCondition(
		&policy.Status.Conditions,
		metav1.Condition{
			Type:               conditionType,
			Status:             status,
			Reason:             reason,
			Message:            message,
			ObservedGeneration: policy.Generation,
		},
	)
}

func (r *IncidentPolicyReconciler) patchIncidentPolicyStatus(
	ctx context.Context,
	before *opsv1alpha1.IncidentPolicy,
	policy *opsv1alpha1.IncidentPolicy,
) error {
	if reflect.DeepEqual(
		before.Status,
		policy.Status,
	) {
		return nil
	}

	if err := r.Status().Patch(
		ctx,
		policy,
		client.MergeFrom(before),
	); err != nil {
		return fmt.Errorf(
			"patch IncidentPolicy status %s/%s: %w",
			policy.Namespace,
			policy.Name,
			err,
		)
	}

	return nil
}

// -----------------------------------------------------------------------------
// CrashLoopBackOff detection
// -----------------------------------------------------------------------------

func findCrashLoopBackOff(
	pods []corev1.Pod,
) []incidentFinding {
	findings :=
		make([]incidentFinding, 0)

	for i := range pods {
		pod :=
			&pods[i]

		for j := range pod.Status.InitContainerStatuses {
			status :=
				&pod.Status.InitContainerStatuses[j]

			if status.State.Waiting == nil {
				continue
			}

			if status.State.Waiting.Reason !=
				"CrashLoopBackOff" {

				continue
			}

			findings = append(
				findings,
				incidentFinding{
					PodName: pod.Name,

					PodUID: string(pod.UID),

					ContainerName: status.Name,

					IncidentType: "CrashLoopBackOff",

					Message: fmt.Sprintf(
						"Container %s in Pod %s is repeatedly failing with CrashLoopBackOff.",
						status.Name,
						pod.Name,
					),

					RestartCount: status.RestartCount,

					CurrentState: "Waiting",

					WaitingReason: status.State.Waiting.Reason,

					LastTerminationReason: containerLastTerminationReason(
						status,
					),

					ExitCode: containerLastExitCode(
						status,
					),
				},
			)
		}

		for j := range pod.Status.ContainerStatuses {
			status :=
				&pod.Status.ContainerStatuses[j]

			if status.State.Waiting == nil {
				continue
			}

			if status.State.Waiting.Reason !=
				"CrashLoopBackOff" {

				continue
			}

			findings = append(
				findings,
				incidentFinding{
					PodName: pod.Name,

					PodUID: string(pod.UID),

					ContainerName: status.Name,

					IncidentType: "CrashLoopBackOff",

					Message: fmt.Sprintf(
						"Container %s in Pod %s is repeatedly failing with CrashLoopBackOff.",
						status.Name,
						pod.Name,
					),

					RestartCount: status.RestartCount,

					CurrentState: "Waiting",

					WaitingReason: status.State.Waiting.Reason,

					LastTerminationReason: containerLastTerminationReason(
						status,
					),

					ExitCode: containerLastExitCode(
						status,
					),
				},
			)
		}
	}

	return findings
}

// -----------------------------------------------------------------------------
// OOMKilled detection
// -----------------------------------------------------------------------------

func findOOMKilled(
	pods []corev1.Pod,
) []incidentFinding {
	findings :=
		make([]incidentFinding, 0)

	for i := range pods {
		pod :=
			&pods[i]

		for j := range pod.Status.InitContainerStatuses {
			status :=
				&pod.Status.InitContainerStatuses[j]

			if status.State.Terminated != nil &&
				status.State.Terminated.Reason == "OOMKilled" {

				findings = append(
					findings,
					newOOMKilledFinding(
						pod,
						status,
						status.State.Terminated,
					),
				)

				continue
			}

			if status.LastTerminationState.Terminated != nil &&
				status.LastTerminationState.Terminated.Reason ==
					"OOMKilled" {

				findings = append(
					findings,
					newOOMKilledFinding(
						pod,
						status,
						status.LastTerminationState.Terminated,
					),
				)
			}
		}

		for j := range pod.Status.ContainerStatuses {
			status :=
				&pod.Status.ContainerStatuses[j]

			if status.State.Terminated != nil &&
				status.State.Terminated.Reason == "OOMKilled" {

				findings = append(
					findings,
					newOOMKilledFinding(
						pod,
						status,
						status.State.Terminated,
					),
				)

				continue
			}

			if status.LastTerminationState.Terminated != nil &&
				status.LastTerminationState.Terminated.Reason ==
					"OOMKilled" {

				findings = append(
					findings,
					newOOMKilledFinding(
						pod,
						status,
						status.LastTerminationState.Terminated,
					),
				)
			}
		}
	}

	return findings
}

func newOOMKilledFinding(
	pod *corev1.Pod,
	status *corev1.ContainerStatus,
	termination *corev1.ContainerStateTerminated,
) incidentFinding {
	exitCode :=
		termination.ExitCode

	return incidentFinding{
		PodName: pod.Name,

		PodUID: string(pod.UID),

		ContainerName: status.Name,

		IncidentType: "OOMKilled",

		Message: fmt.Sprintf(
			"Container %s in Pod %s was terminated with reason OOMKilled.",
			status.Name,
			pod.Name,
		),

		RestartCount: status.RestartCount,

		CurrentState: containerStateName(
			status.State,
		),

		LastTerminationReason: termination.Reason,

		ExitCode: &exitCode,
	}
}

// -----------------------------------------------------------------------------
// Image pull failure detection
// -----------------------------------------------------------------------------

func findImagePullFailures(
	pods []corev1.Pod,
) []incidentFinding {
	findings :=
		make([]incidentFinding, 0)

	for i := range pods {
		pod :=
			&pods[i]

		for j := range pod.Status.InitContainerStatuses {
			status :=
				&pod.Status.InitContainerStatuses[j]

			finding, found :=
				imagePullFinding(
					pod,
					status,
				)

			if found {
				findings = append(
					findings,
					finding,
				)
			}
		}

		for j := range pod.Status.ContainerStatuses {
			status :=
				&pod.Status.ContainerStatuses[j]

			finding, found :=
				imagePullFinding(
					pod,
					status,
				)

			if found {
				findings = append(
					findings,
					finding,
				)
			}
		}
	}

	return findings
}

func imagePullFinding(
	pod *corev1.Pod,
	status *corev1.ContainerStatus,
) (incidentFinding, bool) {
	if status.State.Waiting == nil {
		return incidentFinding{}, false
	}

	reason :=
		status.State.Waiting.Reason

	if reason != "ErrImagePull" &&
		reason != "ImagePullBackOff" {

		return incidentFinding{}, false
	}

	return incidentFinding{
		PodName: pod.Name,

		PodUID: string(pod.UID),

		ContainerName: status.Name,

		IncidentType: reason,

		Message: fmt.Sprintf(
			"Container %s in Pod %s cannot pull its image: %s.",
			status.Name,
			pod.Name,
			reason,
		),

		RestartCount: status.RestartCount,

		CurrentState: "Waiting",

		WaitingReason: reason,

		LastTerminationReason: containerLastTerminationReason(
			status,
		),

		ExitCode: containerLastExitCode(
			status,
		),
	}, true
}

// -----------------------------------------------------------------------------
// Container state helpers
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

func containerLastTerminationReason(
	status *corev1.ContainerStatus,
) string {
	if status.State.Terminated != nil {
		return status.State.Terminated.Reason
	}

	if status.LastTerminationState.Terminated != nil {
		return status.LastTerminationState.Terminated.Reason
	}

	return ""
}

func containerLastExitCode(
	status *corev1.ContainerStatus,
) *int32 {
	if status.State.Terminated != nil {
		exitCode :=
			status.State.Terminated.ExitCode

		return &exitCode
	}

	if status.LastTerminationState.Terminated != nil {
		exitCode :=
			status.LastTerminationState.Terminated.ExitCode

		return &exitCode
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
	raw :=
		fmt.Sprintf(
			"%s|%s|%s|%s",
			string(policy.UID),
			finding.PodUID,
			finding.ContainerName,
			finding.IncidentType,
		)

	sum :=
		sha256.Sum256(
			[]byte(raw),
		)

	return fmt.Sprintf(
		"%x",
		sum,
	)
}

func incidentReportName(
	fingerprint string,
) string {
	const prefixLength = 16

	if len(fingerprint) <= prefixLength {
		return "incident-" + fingerprint
	}

	return "incident-" +
		fingerprint[:prefixLength]
}

// -----------------------------------------------------------------------------
// IncidentReport creation / retrieval
//
// The report name is deterministic.
//
// Concurrent reconciles may race:
//
// Reconcile A                   Reconcile B
// GET -> NotFound               GET -> NotFound
// CREATE -> success             CREATE -> AlreadyExists
//
// AlreadyExists is therefore recovered by re-reading the existing report.
// -----------------------------------------------------------------------------

func (r *IncidentPolicyReconciler) ensureIncidentReport(
	ctx context.Context,
	policy *opsv1alpha1.IncidentPolicy,
	finding *incidentFinding,
	fingerprint string,
) error {
	reportName := incidentReportName(fingerprint)

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

	if err == nil {
		// A deterministic report name must always represent the same
		// incident fingerprint.
		if report.Spec.Fingerprint != fingerprint {
			return fmt.Errorf(
				"IncidentReport name collision for %s: expected fingerprint %s, found %s",
				reportName,
				fingerprint,
				report.Spec.Fingerprint,
			)
		}

		return r.updateIncidentReportStatus(
			ctx,
			report,
			finding,
		)
	}

	if !apierrors.IsNotFound(err) {
		return fmt.Errorf(
			"get IncidentReport %s/%s: %w",
			policy.Namespace,
			reportName,
			err,
		)
	}

	report = &opsv1alpha1.IncidentReport{
		ObjectMeta: metav1.ObjectMeta{
			Name:      reportName,
			Namespace: policy.Namespace,
			Labels: map[string]string{
				reportPolicyUIDLabel:    string(policy.UID),
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

	err = r.Create(
		ctx,
		report,
	)

	if err != nil {
		if !apierrors.IsAlreadyExists(err) {
			return fmt.Errorf(
				"create IncidentReport %s/%s: %w",
				policy.Namespace,
				reportName,
				err,
			)
		}

		// Another reconciliation created the deterministic report after
		// our original GET returned NotFound.
		report = &opsv1alpha1.IncidentReport{}

		if getErr := r.Get(
			ctx,
			key,
			report,
		); getErr != nil {
			return fmt.Errorf(
				"get concurrently created IncidentReport %s/%s: %w",
				policy.Namespace,
				reportName,
				getErr,
			)
		}

		if report.Spec.Fingerprint != fingerprint {
			return fmt.Errorf(
				"IncidentReport name collision for %s: expected fingerprint %s, found %s",
				reportName,
				fingerprint,
				report.Spec.Fingerprint,
			)
		}
	} else {
		// A new IncidentReport was actually created by this reconciliation.
		//
		// Repeated reconciliations will GET the existing report and will not
		// increment this metric again.
		incidentReportTransitionsTotal.WithLabelValues(
			"created",
		).Inc()
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
	log :=
		logf.FromContext(
			ctx,
		)

	before :=
		report.DeepCopy()

	now :=
		metav1.Now()

	if report.Status.FirstDetectedAt == nil {
		firstDetected :=
			now

		report.Status.FirstDetectedAt =
			&firstDetected
	}

	lastObserved :=
		now

	report.Status.LastObservedAt =
		&lastObserved

	report.Status.Phase =
		"Active"

	report.Status.ResolvedAt =
		nil

	// -----------------------------------------------------------------
	// Pod/container evidence.
	//
	// Failure here is supplemental. Detector-derived evidence remains
	// available and the incident is still recorded.
	// -----------------------------------------------------------------

	evidence, podEvidenceErr :=
		r.collectPodContainerEvidence(
			ctx,
			report.Namespace,
			finding,
		)

	if podEvidenceErr != nil {
		// -------------------------------------------------------------
		// Phase 6.2D:
		// Evidence collection failure metric.
		// -------------------------------------------------------------

		evidenceCollectionFailuresTotal.WithLabelValues(
			"pod",
		).Inc()

		log.Error(
			podEvidenceErr,
			"failed to collect Pod/container evidence",
			"incidentReport",
			report.Name,
			"pod",
			finding.PodName,
			"container",
			finding.ContainerName,
		)
	}

	// -----------------------------------------------------------------
	// Kubernetes Event evidence.
	//
	// If refresh fails, retain the previously collected Events.
	// -----------------------------------------------------------------

	eventEvidence, eventErr :=
		r.collectPodEventEvidence(
			ctx,
			report.Namespace,
			finding.PodUID,
		)

	if eventErr != nil {
		// -------------------------------------------------------------
		// Phase 6.2D:
		// Evidence collection failure metric.
		// -------------------------------------------------------------

		evidenceCollectionFailuresTotal.WithLabelValues(
			"event",
		).Inc()

		log.Error(
			eventErr,
			"failed to collect Kubernetes Event evidence",
			"incidentReport",
			report.Name,
			"pod",
			finding.PodName,
		)

		evidence.Events =
			before.Status.Evidence.Events
	} else {
		evidence.Events =
			eventEvidence
	}

	// -----------------------------------------------------------------
	// Bounded container logs.
	//
	// Log evidence is supplemental. Failure must never invalidate the
	// primary incident.
	// -----------------------------------------------------------------

	if r.LogReader == nil {
		// envtest does not have a kubelet log endpoint unless a fake reader
		// is explicitly injected.
		evidence.Logs =
			before.Status.Evidence.Logs
	} else {
		logEvidence, logErr :=
			r.collectContainerLogEvidence(
				ctx,
				report.Namespace,
				finding,
			)

		if logErr != nil {
			// ---------------------------------------------------------
			// Phase 6.2D:
			// Evidence collection failure metric.
			// ---------------------------------------------------------

			evidenceCollectionFailuresTotal.WithLabelValues(
				"log",
			).Inc()

			log.Error(
				logErr,
				"failed to collect some container log evidence",
				"incidentReport",
				report.Name,
				"pod",
				finding.PodName,
				"container",
				finding.ContainerName,
			)
		}

		if logEvidence.CollectedAt != nil {
			// At least one log request succeeded.
			evidence.Logs =
				logEvidence
		} else if logErr != nil {
			// Every requested log read failed.
			//
			// Preserve older evidence instead of replacing useful history
			// with an empty structure.
			evidence.Logs =
				before.Status.Evidence.Logs
		}
	}

	report.Status.Evidence =
		evidence

	if reflect.DeepEqual(
		before.Status,
		report.Status,
	) {
		return nil
	}

	if err :=
		r.Status().Patch(
			ctx,
			report,
			client.MergeFrom(before),
		); err != nil {

		return fmt.Errorf(
			"patch IncidentReport status %s/%s: %w",
			report.Namespace,
			report.Name,
			err,
		)
	}

	return nil
}

// -----------------------------------------------------------------------------
// Resolve IncidentReports that are no longer observed
// -----------------------------------------------------------------------------

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
		return fmt.Errorf(
			"list IncidentReports for IncidentPolicy %s/%s: %w",
			policy.Namespace,
			policy.Name,
			err,
		)
	}

	for i := range reports.Items {
		report := &reports.Items[i]

		// Only Active reports can transition to Resolved.
		if report.Status.Phase != "Active" {
			continue
		}

		// The incident is still present during this reconciliation.
		if _, stillObserved := observedFingerprints[report.Spec.Fingerprint]; stillObserved {
			continue
		}

		before := report.DeepCopy()

		now := metav1.Now()

		report.Status.Phase = "Resolved"
		report.Status.ResolvedAt = &now

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
			return fmt.Errorf(
				"resolve IncidentReport %s/%s: %w",
				report.Namespace,
				report.Name,
				err,
			)
		}

		// Count the transition only after the status update succeeds.
		//
		// On the next reconciliation this report is already Resolved,
		// therefore it cannot increment the metric again.
		incidentReportTransitionsTotal.WithLabelValues(
			"resolved",
		).Inc()
	}

	return nil
}

// -----------------------------------------------------------------------------
// Pod -> IncidentPolicy event mapping
//
// A Pod update should reconcile every IncidentPolicy in the same namespace
// whose selector matches that Pod.
// -----------------------------------------------------------------------------

func (r *IncidentPolicyReconciler) mapPodToIncidentPolicies(
	ctx context.Context,
	obj client.Object,
) []reconcile.Request {
	pod, ok :=
		obj.(*corev1.Pod)

	if !ok {
		return nil
	}

	policies :=
		&opsv1alpha1.IncidentPolicyList{}

	if err :=
		r.List(
			ctx,
			policies,
			client.InNamespace(
				pod.Namespace,
			),
		); err != nil {

		logf.FromContext(ctx).Error(
			err,
			"failed to list IncidentPolicies while mapping Pod event",
			"pod",
			pod.Name,
			"namespace",
			pod.Namespace,
		)

		return nil
	}

	requests :=
		make([]reconcile.Request, 0)

	podLabels :=
		labels.Set(
			pod.Labels,
		)

	for i := range policies.Items {
		policy :=
			&policies.Items[i]

		selector, err :=
			metav1.LabelSelectorAsSelector(
				&policy.Spec.Selector,
			)

		if err != nil {
			continue
		}

		if !selector.Matches(
			podLabels,
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
// Controller setup
// -----------------------------------------------------------------------------

func (r *IncidentPolicyReconciler) SetupWithManager(
	mgr ctrl.Manager,
) error {
	// Production receives the real Kubernetes Pod log reader.
	//
	// Tests can inject a fake reader before SetupWithManager if needed.
	if r.LogReader == nil {
		logReader, err :=
			newKubernetesLogReader(
				mgr.GetConfig(),
			)

		if err != nil {
			return fmt.Errorf(
				"initialize Kubernetes log reader: %w",
				err,
			)
		}

		r.LogReader =
			logReader
	}

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

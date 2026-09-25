package controller

import (
	opsv1alpha1 "github.com/yashshrivastav22/kubetriage/api/v1alpha1"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

var _ = Describe("IncidentReport lifecycle", func() {

	BeforeEach(func() {
		namespace := &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name: controllerTestNamespace,
			},
		}

		err := k8sClient.Create(
			ctx,
			namespace,
		)

		if err != nil &&
			!apierrors.IsAlreadyExists(err) {
			Expect(err).NotTo(HaveOccurred())
		}
	})

	// ---------------------------------------------------------------------
	// TEST 1:
	// Same incident must reuse one IncidentReport.
	// ---------------------------------------------------------------------

	It("reuses one IncidentReport for repeated observations of the same incident", func() {
		pod := createLifecyclePod(
			"dedupe-crash-pod",
			map[string]string{
				"app": "dedupe-test",
			},
			corev1.ContainerState{
				Waiting: &corev1.ContainerStateWaiting{
					Reason:  "CrashLoopBackOff",
					Message: "back-off restarting failed container",
				},
			},
			corev1.ContainerState{},
			3,
		)

		policy := &opsv1alpha1.IncidentPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "dedupe-policy",
				Namespace: controllerTestNamespace,
			},

			Spec: opsv1alpha1.IncidentPolicySpec{
				Selector: metav1.LabelSelector{
					MatchLabels: map[string]string{
						"app": "dedupe-test",
					},
				},

				Checks: opsv1alpha1.IncidentChecks{
					CrashLoop: true,
				},
			},
		}

		Expect(
			k8sClient.Create(
				ctx,
				policy,
			),
		).To(Succeed())

		// First reconciliation.
		reconcilePolicy(
			policy.Name,
		)

		firstReports := listReportsForPolicy(
			policy,
		)

		Expect(
			firstReports.Items,
		).To(HaveLen(1))

		firstReport := &firstReports.Items[0]

		Expect(
			firstReport.Status.Phase,
		).To(Equal("Active"))

		Expect(
			firstReport.Status.FirstDetectedAt,
		).NotTo(BeNil())

		Expect(
			firstReport.Status.LastObservedAt,
		).NotTo(BeNil())

		Expect(
			firstReport.Status.Evidence.RestartCount,
		).To(Equal(int32(3)))

		firstName :=
			firstReport.Name

		firstFingerprint :=
			firstReport.Spec.Fingerprint

		firstDetectedAt :=
			firstReport.Status.FirstDetectedAt.Time

		// -------------------------------------------------------------
		// Same incident continues.
		// -------------------------------------------------------------

		pod.Status.ContainerStatuses[0].RestartCount = 4

		Expect(
			k8sClient.Status().Update(
				ctx,
				pod,
			),
		).To(Succeed())

		// Second reconciliation.
		reconcilePolicy(
			policy.Name,
		)

		secondReports := listReportsForPolicy(
			policy,
		)

		// Critical deduplication check.
		Expect(
			secondReports.Items,
		).To(HaveLen(1))

		secondReport :=
			&secondReports.Items[0]

		Expect(
			secondReport.Name,
		).To(Equal(firstName))

		Expect(
			secondReport.Spec.Fingerprint,
		).To(Equal(firstFingerprint))

		Expect(
			secondReport.Status.Phase,
		).To(Equal("Active"))

		Expect(
			secondReport.Status.FirstDetectedAt.Time.Equal(
				firstDetectedAt,
			),
		).To(BeTrue())

		Expect(
			secondReport.Status.Evidence.RestartCount,
		).To(Equal(int32(4)))
	})

	// ---------------------------------------------------------------------
	// TEST 2:
	// Active incident must become Resolved when the failure disappears.
	// ---------------------------------------------------------------------

	It("marks an Active IncidentReport Resolved when the failure disappears", func() {
		pod := createLifecyclePod(
			"resolution-crash-pod",
			map[string]string{
				"app": "resolution-test",
			},
			corev1.ContainerState{
				Waiting: &corev1.ContainerStateWaiting{
					Reason: "CrashLoopBackOff",
				},
			},
			corev1.ContainerState{},
			5,
		)

		policy := &opsv1alpha1.IncidentPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "resolution-policy",
				Namespace: controllerTestNamespace,
			},

			Spec: opsv1alpha1.IncidentPolicySpec{
				Selector: metav1.LabelSelector{
					MatchLabels: map[string]string{
						"app": "resolution-test",
					},
				},

				Checks: opsv1alpha1.IncidentChecks{
					CrashLoop: true,
				},
			},
		}

		Expect(
			k8sClient.Create(
				ctx,
				policy,
			),
		).To(Succeed())

		// Detect initial incident.
		reconcilePolicy(
			policy.Name,
		)

		activeReports := listReportsForPolicy(
			policy,
		)

		Expect(
			activeReports.Items,
		).To(HaveLen(1))

		activeReport :=
			&activeReports.Items[0]

		Expect(
			activeReport.Status.Phase,
		).To(Equal("Active"))

		Expect(
			activeReport.Status.ResolvedAt,
		).To(BeNil())

		reportName :=
			activeReport.Name

		fingerprint :=
			activeReport.Spec.Fingerprint

		firstDetectedAt :=
			activeReport.Status.FirstDetectedAt.Time

		lastObservedAt :=
			activeReport.Status.LastObservedAt.Time

		restartCount :=
			activeReport.Status.Evidence.RestartCount

		// -------------------------------------------------------------
		// Simulate recovery.
		// -------------------------------------------------------------

		pod.Status.ContainerStatuses =
			[]corev1.ContainerStatus{
				{
					Name:         "app",
					RestartCount: 5,

					State: corev1.ContainerState{
						Running: &corev1.ContainerStateRunning{},
					},
				},
			}

		Expect(
			k8sClient.Status().Update(
				ctx,
				pod,
			),
		).To(Succeed())

		updatedPolicy := reconcilePolicy(
			policy.Name,
		)

		condition :=
			apimeta.FindStatusCondition(
				updatedPolicy.Status.Conditions,
				conditionTypeIncidentDetected,
			)

		Expect(condition).NotTo(BeNil())

		Expect(
			condition.Status,
		).To(Equal(metav1.ConditionFalse))

		Expect(
			condition.Reason,
		).To(Equal("NoIncidentDetected"))

		// -------------------------------------------------------------
		// Report remains as history but is now Resolved.
		// -------------------------------------------------------------

		resolvedReports := listReportsForPolicy(
			policy,
		)

		Expect(
			resolvedReports.Items,
		).To(HaveLen(1))

		resolvedReport :=
			&resolvedReports.Items[0]

		Expect(
			resolvedReport.Name,
		).To(Equal(reportName))

		Expect(
			resolvedReport.Spec.Fingerprint,
		).To(Equal(fingerprint))

		Expect(
			resolvedReport.Status.Phase,
		).To(Equal("Resolved"))

		Expect(
			resolvedReport.Status.ResolvedAt,
		).NotTo(BeNil())

		// Historical timestamps must remain intact.
		Expect(
			resolvedReport.Status.FirstDetectedAt.Time.Equal(
				firstDetectedAt,
			),
		).To(BeTrue())

		Expect(
			resolvedReport.Status.LastObservedAt.Time.Equal(
				lastObservedAt,
			),
		).To(BeTrue())

		// Evidence from the incident must remain available.
		Expect(
			resolvedReport.Status.Evidence.RestartCount,
		).To(Equal(restartCount))

		Expect(
			resolvedReport.Status.Evidence.WaitingReason,
		).To(Equal("CrashLoopBackOff"))
	})

	// ---------------------------------------------------------------------
	// TEST 3:
	// Multiple failures must generate multiple IncidentReports.
	// ---------------------------------------------------------------------

	It("creates separate Active IncidentReports for simultaneous incidents", func() {

		// -------------------------------------------------------------
		// CrashLoopBackOff Pod.
		// -------------------------------------------------------------

		createLifecyclePod(
			"multi-crash-pod",
			map[string]string{
				"app": "multi-incident-test",
			},
			corev1.ContainerState{
				Waiting: &corev1.ContainerStateWaiting{
					Reason: "CrashLoopBackOff",
				},
			},
			corev1.ContainerState{},
			4,
		)

		// -------------------------------------------------------------
		// OOMKilled Pod.
		//
		// Container is currently running, but the previous termination
		// was OOMKilled.
		// -------------------------------------------------------------

		createLifecyclePod(
			"multi-oom-pod",
			map[string]string{
				"app": "multi-incident-test",
			},
			corev1.ContainerState{
				Running: &corev1.ContainerStateRunning{},
			},
			corev1.ContainerState{
				Terminated: &corev1.ContainerStateTerminated{
					Reason:   "OOMKilled",
					ExitCode: 137,
				},
			},
			2,
		)

		// -------------------------------------------------------------
		// ImagePullBackOff Pod.
		// -------------------------------------------------------------

		createLifecyclePod(
			"multi-image-pod",
			map[string]string{
				"app": "multi-incident-test",
			},
			corev1.ContainerState{
				Waiting: &corev1.ContainerStateWaiting{
					Reason: "ImagePullBackOff",
				},
			},
			corev1.ContainerState{},
			0,
		)

		policy := &opsv1alpha1.IncidentPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "multi-incident-policy",
				Namespace: controllerTestNamespace,
			},

			Spec: opsv1alpha1.IncidentPolicySpec{
				Selector: metav1.LabelSelector{
					MatchLabels: map[string]string{
						"app": "multi-incident-test",
					},
				},

				Checks: opsv1alpha1.IncidentChecks{
					CrashLoop: true,
					OOMKilled: true,
					ImagePull: true,
				},
			},
		}

		Expect(
			k8sClient.Create(
				ctx,
				policy,
			),
		).To(Succeed())

		updatedPolicy :=
			reconcilePolicy(
				policy.Name,
			)

		// -------------------------------------------------------------
		// Policy summary should indicate multiple incidents.
		// -------------------------------------------------------------

		condition :=
			apimeta.FindStatusCondition(
				updatedPolicy.Status.Conditions,
				conditionTypeIncidentDetected,
			)

		Expect(condition).NotTo(BeNil())

		Expect(
			condition.Status,
		).To(Equal(metav1.ConditionTrue))

		Expect(
			condition.Reason,
		).To(Equal("MultipleIncidentsDetected"))

		Expect(
			condition.Message,
		).To(ContainSubstring("3 active incidents"))

		// -------------------------------------------------------------
		// Exactly three IncidentReports should exist.
		// -------------------------------------------------------------

		reports := listReportsForPolicy(
			policy,
		)

		Expect(
			reports.Items,
		).To(HaveLen(3))

		reportsByType :=
			reportMapByIncidentType(
				reports,
			)

		Expect(
			reportsByType,
		).To(HaveKey("CrashLoopBackOff"))

		Expect(
			reportsByType,
		).To(HaveKey("OOMKilled"))

		Expect(
			reportsByType,
		).To(HaveKey("ImagePullBackOff"))

		Expect(
			reportsByType["CrashLoopBackOff"].Status.Phase,
		).To(Equal("Active"))

		Expect(
			reportsByType["OOMKilled"].Status.Phase,
		).To(Equal("Active"))

		Expect(
			reportsByType["ImagePullBackOff"].Status.Phase,
		).To(Equal("Active"))

		// -------------------------------------------------------------
		// Verify evidence was collected independently.
		// -------------------------------------------------------------

		Expect(
			reportsByType["CrashLoopBackOff"].
				Status.Evidence.WaitingReason,
		).To(Equal("CrashLoopBackOff"))

		Expect(
			reportsByType["OOMKilled"].
				Status.Evidence.LastTerminationReason,
		).To(Equal("OOMKilled"))

		Expect(
			reportsByType["OOMKilled"].
				Status.Evidence.ExitCode,
		).NotTo(BeNil())

		Expect(
			*reportsByType["OOMKilled"].
				Status.Evidence.ExitCode,
		).To(Equal(int32(137)))

		Expect(
			reportsByType["ImagePullBackOff"].
				Status.Evidence.WaitingReason,
		).To(Equal("ImagePullBackOff"))
	})

	// ---------------------------------------------------------------------
	// TEST 4:
	// One incident can resolve while another remains Active.
	// ---------------------------------------------------------------------

	It("resolves one incident independently while another remains Active", func() {

		// -------------------------------------------------------------
		// Pod A: CrashLoopBackOff.
		// -------------------------------------------------------------

		crashPod := createLifecyclePod(
			"partial-crash-pod",
			map[string]string{
				"app": "partial-recovery-test",
			},
			corev1.ContainerState{
				Waiting: &corev1.ContainerStateWaiting{
					Reason: "CrashLoopBackOff",
				},
			},
			corev1.ContainerState{},
			6,
		)

		// -------------------------------------------------------------
		// Pod B: OOMKilled.
		// -------------------------------------------------------------

		createLifecyclePod(
			"partial-oom-pod",
			map[string]string{
				"app": "partial-recovery-test",
			},
			corev1.ContainerState{
				Running: &corev1.ContainerStateRunning{},
			},
			corev1.ContainerState{
				Terminated: &corev1.ContainerStateTerminated{
					Reason:   "OOMKilled",
					ExitCode: 137,
				},
			},
			1,
		)

		policy := &opsv1alpha1.IncidentPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "partial-recovery-policy",
				Namespace: controllerTestNamespace,
			},

			Spec: opsv1alpha1.IncidentPolicySpec{
				Selector: metav1.LabelSelector{
					MatchLabels: map[string]string{
						"app": "partial-recovery-test",
					},
				},

				Checks: opsv1alpha1.IncidentChecks{
					CrashLoop: true,
					OOMKilled: true,
				},
			},
		}

		Expect(
			k8sClient.Create(
				ctx,
				policy,
			),
		).To(Succeed())

		// -------------------------------------------------------------
		// Initial reconciliation:
		//
		// CrashLoop = Active
		// OOMKilled = Active
		// -------------------------------------------------------------

		firstPolicy :=
			reconcilePolicy(
				policy.Name,
			)

		firstCondition :=
			apimeta.FindStatusCondition(
				firstPolicy.Status.Conditions,
				conditionTypeIncidentDetected,
			)

		Expect(firstCondition).NotTo(BeNil())

		Expect(
			firstCondition.Reason,
		).To(Equal("MultipleIncidentsDetected"))

		initialReports :=
			listReportsForPolicy(
				policy,
			)

		Expect(
			initialReports.Items,
		).To(HaveLen(2))

		initialByType :=
			reportMapByIncidentType(
				initialReports,
			)

		Expect(
			initialByType["CrashLoopBackOff"].
				Status.Phase,
		).To(Equal("Active"))

		Expect(
			initialByType["OOMKilled"].
				Status.Phase,
		).To(Equal("Active"))

		crashFingerprint :=
			initialByType["CrashLoopBackOff"].
				Spec.Fingerprint

		oomFingerprint :=
			initialByType["OOMKilled"].
				Spec.Fingerprint

		// -------------------------------------------------------------
		// CrashLoop Pod recovers.
		//
		// OOMKilled evidence on the other Pod still exists.
		// -------------------------------------------------------------

		crashPod.Status.ContainerStatuses =
			[]corev1.ContainerStatus{
				{
					Name:         "app",
					RestartCount: 6,

					State: corev1.ContainerState{
						Running: &corev1.ContainerStateRunning{},
					},
				},
			}

		Expect(
			k8sClient.Status().Update(
				ctx,
				crashPod,
			),
		).To(Succeed())

		// -------------------------------------------------------------
		// Reconcile again.
		// -------------------------------------------------------------

		secondPolicy :=
			reconcilePolicy(
				policy.Name,
			)

		secondCondition :=
			apimeta.FindStatusCondition(
				secondPolicy.Status.Conditions,
				conditionTypeIncidentDetected,
			)

		Expect(secondCondition).NotTo(BeNil())

		// Only OOMKilled remains, so the summary returns to the
		// single-incident reason.
		Expect(
			secondCondition.Status,
		).To(Equal(metav1.ConditionTrue))

		Expect(
			secondCondition.Reason,
		).To(Equal("OOMKilledDetected"))

		// -------------------------------------------------------------
		// Both historical reports still exist.
		// -------------------------------------------------------------

		finalReports :=
			listReportsForPolicy(
				policy,
			)

		Expect(
			finalReports.Items,
		).To(HaveLen(2))

		finalByType :=
			reportMapByIncidentType(
				finalReports,
			)

		// CrashLoop report is independently resolved.
		Expect(
			finalByType["CrashLoopBackOff"].
				Status.Phase,
		).To(Equal("Resolved"))

		Expect(
			finalByType["CrashLoopBackOff"].
				Status.ResolvedAt,
		).NotTo(BeNil())

		// OOMKilled report remains Active.
		Expect(
			finalByType["OOMKilled"].
				Status.Phase,
		).To(Equal("Active"))

		Expect(
			finalByType["OOMKilled"].
				Status.ResolvedAt,
		).To(BeNil())

		// Neither report identity changed.
		Expect(
			finalByType["CrashLoopBackOff"].
				Spec.Fingerprint,
		).To(Equal(crashFingerprint))

		Expect(
			finalByType["OOMKilled"].
				Spec.Fingerprint,
		).To(Equal(oomFingerprint))
	})
})

// -----------------------------------------------------------------------------
// Test helpers
// -----------------------------------------------------------------------------

// createLifecyclePod creates a Pod and simulates the status normally
// maintained by kubelet.
//
// envtest runs an API server and etcd but does not run kubelet, so Pod
// container status must be written explicitly by the test.
func createLifecyclePod(
	name string,
	podLabels map[string]string,
	state corev1.ContainerState,
	lastTerminationState corev1.ContainerState,
	restartCount int32,
) *corev1.Pod {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: controllerTestNamespace,
			Labels:    podLabels,
		},

		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{
					Name:  "app",
					Image: "busybox:1.36",
				},
			},
		},
	}

	Expect(
		k8sClient.Create(
			ctx,
			pod,
		),
	).To(Succeed())

	pod.Status.ContainerStatuses =
		[]corev1.ContainerStatus{
			{
				Name:                 "app",
				RestartCount:         restartCount,
				State:                state,
				LastTerminationState: lastTerminationState,
			},
		}

	Expect(
		k8sClient.Status().Update(
			ctx,
			pod,
		),
	).To(Succeed())

	return pod
}

// listReportsForPolicy returns only IncidentReports created for the supplied
// IncidentPolicy.
func listReportsForPolicy(
	policy *opsv1alpha1.IncidentPolicy,
) *opsv1alpha1.IncidentReportList {
	reports :=
		&opsv1alpha1.IncidentReportList{}

	Expect(
		k8sClient.List(
			ctx,
			reports,

			client.InNamespace(
				controllerTestNamespace,
			),

			client.MatchingLabels{
				reportPolicyUIDLabel: string(policy.UID),
			},
		),
	).To(Succeed())

	return reports
}

// reportMapByIncidentType makes multi-incident assertions easier to read.
func reportMapByIncidentType(
	reports *opsv1alpha1.IncidentReportList,
) map[string]*opsv1alpha1.IncidentReport {
	result :=
		make(
			map[string]*opsv1alpha1.IncidentReport,
		)

	for i := range reports.Items {
		report :=
			&reports.Items[i]

		result[report.Spec.IncidentType] =
			report
	}

	return result
}

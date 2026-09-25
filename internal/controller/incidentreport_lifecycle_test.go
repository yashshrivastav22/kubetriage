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
	// Repeated observations of the same incident must reuse one report.
	// ---------------------------------------------------------------------

	It("creates one Active IncidentReport and reuses it for repeated observations", func() {

		pod := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "checkout-lifecycle-crash",
				Namespace: controllerTestNamespace,
				Labels: map[string]string{
					"app": "checkout-lifecycle-test",
				},
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

		// envtest has no kubelet, so container status must be simulated.
		pod.Status.ContainerStatuses = []corev1.ContainerStatus{
			{
				Name:         "app",
				RestartCount: 3,

				State: corev1.ContainerState{
					Waiting: &corev1.ContainerStateWaiting{
						Reason:  "CrashLoopBackOff",
						Message: "back-off restarting failed container",
					},
				},
			},
		}

		Expect(
			k8sClient.Status().Update(
				ctx,
				pod,
			),
		).To(Succeed())

		policy := &opsv1alpha1.IncidentPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "checkout-lifecycle-policy",
				Namespace: controllerTestNamespace,
			},

			Spec: opsv1alpha1.IncidentPolicySpec{
				Selector: metav1.LabelSelector{
					MatchLabels: map[string]string{
						"app": "checkout-lifecycle-test",
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

		// -------------------------------------------------------------
		// First reconciliation.
		// -------------------------------------------------------------

		updatedPolicy := reconcilePolicy(
			policy.Name,
		)

		incidentCondition := apimeta.FindStatusCondition(
			updatedPolicy.Status.Conditions,
			conditionTypeIncidentDetected,
		)

		Expect(
			incidentCondition,
		).NotTo(BeNil())

		Expect(
			incidentCondition.Status,
		).To(Equal(metav1.ConditionTrue))

		Expect(
			incidentCondition.Reason,
		).To(Equal("CrashLoopBackOffDetected"))

		// -------------------------------------------------------------
		// Find the created IncidentReport.
		// -------------------------------------------------------------

		firstReports := &opsv1alpha1.IncidentReportList{}

		Expect(
			k8sClient.List(
				ctx,
				firstReports,

				client.InNamespace(
					controllerTestNamespace,
				),

				client.MatchingLabels{
					reportPolicyUIDLabel: string(policy.UID),
				},
			),
		).To(Succeed())

		Expect(
			firstReports.Items,
		).To(HaveLen(1))

		firstReport :=
			&firstReports.Items[0]

		// -------------------------------------------------------------
		// Verify stable identity.
		// -------------------------------------------------------------

		Expect(
			firstReport.Spec.PolicyName,
		).To(Equal(policy.Name))

		Expect(
			firstReport.Spec.PolicyUID,
		).To(Equal(string(policy.UID)))

		Expect(
			firstReport.Spec.PodName,
		).To(Equal(pod.Name))

		Expect(
			firstReport.Spec.PodUID,
		).To(Equal(string(pod.UID)))

		Expect(
			firstReport.Spec.ContainerName,
		).To(Equal("app"))

		Expect(
			firstReport.Spec.IncidentType,
		).To(Equal("CrashLoopBackOff"))

		Expect(
			firstReport.Spec.Fingerprint,
		).NotTo(BeEmpty())

		firstReportName :=
			firstReport.Name

		firstFingerprint :=
			firstReport.Spec.Fingerprint

		// -------------------------------------------------------------
		// Verify Active lifecycle.
		// -------------------------------------------------------------

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
			firstReport.Status.ResolvedAt,
		).To(BeNil())

		firstDetectedTime :=
			firstReport.Status.FirstDetectedAt.Time

		firstObservedTime :=
			firstReport.Status.LastObservedAt.Time

		// -------------------------------------------------------------
		// Verify evidence.
		// -------------------------------------------------------------

		Expect(
			firstReport.Status.Evidence.RestartCount,
		).To(Equal(int32(3)))

		Expect(
			firstReport.Status.Evidence.CurrentState,
		).To(Equal("Waiting"))

		Expect(
			firstReport.Status.Evidence.WaitingReason,
		).To(Equal("CrashLoopBackOff"))

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

		// -------------------------------------------------------------
		// List reports again.
		// -------------------------------------------------------------

		secondReports :=
			&opsv1alpha1.IncidentReportList{}

		Expect(
			k8sClient.List(
				ctx,
				secondReports,

				client.InNamespace(
					controllerTestNamespace,
				),

				client.MatchingLabels{
					reportPolicyUIDLabel: string(policy.UID),
				},
			),
		).To(Succeed())

		// Critical duplicate-prevention assertion.
		Expect(
			secondReports.Items,
		).To(HaveLen(1))

		secondReport :=
			&secondReports.Items[0]

		// Same resource.
		Expect(
			secondReport.Name,
		).To(Equal(firstReportName))

		// Same fingerprint.
		Expect(
			secondReport.Spec.Fingerprint,
		).To(Equal(firstFingerprint))

		Expect(
			secondReport.Status.Phase,
		).To(Equal("Active"))

		// FirstDetectedAt must stay unchanged.
		Expect(
			secondReport.Status.FirstDetectedAt,
		).NotTo(BeNil())

		Expect(
			secondReport.Status.FirstDetectedAt.Time.Equal(
				firstDetectedTime,
			),
		).To(BeTrue())

		// LastObservedAt must not move backwards.
		Expect(
			secondReport.Status.LastObservedAt,
		).NotTo(BeNil())

		Expect(
			secondReport.Status.LastObservedAt.Time.Before(
				firstObservedTime,
			),
		).To(BeFalse())

		// Evidence should refresh.
		Expect(
			secondReport.Status.Evidence.RestartCount,
		).To(Equal(int32(4)))

		Expect(
			secondReport.Status.Evidence.CurrentState,
		).To(Equal("Waiting"))

		Expect(
			secondReport.Status.Evidence.WaitingReason,
		).To(Equal("CrashLoopBackOff"))

		Expect(
			secondReport.Status.ResolvedAt,
		).To(BeNil())
	})

	// ---------------------------------------------------------------------
	// TEST 2:
	// Active incident becomes Resolved when the failure disappears.
	// ---------------------------------------------------------------------

	It("marks an Active IncidentReport Resolved when the Pod becomes healthy", func() {

		// -------------------------------------------------------------
		// STEP 1:
		// Create a crashing Pod.
		// -------------------------------------------------------------

		pod := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "checkout-resolution-pod",
				Namespace: controllerTestNamespace,
				Labels: map[string]string{
					"app": "checkout-resolution-test",
				},
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
					Name:         "app",
					RestartCount: 5,

					State: corev1.ContainerState{
						Waiting: &corev1.ContainerStateWaiting{
							Reason:  "CrashLoopBackOff",
							Message: "back-off restarting failed container",
						},
					},
				},
			}

		Expect(
			k8sClient.Status().Update(
				ctx,
				pod,
			),
		).To(Succeed())

		// -------------------------------------------------------------
		// STEP 2:
		// Create policy.
		// -------------------------------------------------------------

		policy := &opsv1alpha1.IncidentPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "checkout-resolution-policy",
				Namespace: controllerTestNamespace,
			},

			Spec: opsv1alpha1.IncidentPolicySpec{
				Selector: metav1.LabelSelector{
					MatchLabels: map[string]string{
						"app": "checkout-resolution-test",
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

		// -------------------------------------------------------------
		// STEP 3:
		// Detect the incident.
		// -------------------------------------------------------------

		reconcilePolicy(
			policy.Name,
		)

		activeReports :=
			&opsv1alpha1.IncidentReportList{}

		Expect(
			k8sClient.List(
				ctx,
				activeReports,

				client.InNamespace(
					controllerTestNamespace,
				),

				client.MatchingLabels{
					reportPolicyUIDLabel: string(policy.UID),
				},
			),
		).To(Succeed())

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

		Expect(
			activeReport.Status.FirstDetectedAt,
		).NotTo(BeNil())

		Expect(
			activeReport.Status.LastObservedAt,
		).NotTo(BeNil())

		reportName :=
			activeReport.Name

		fingerprint :=
			activeReport.Spec.Fingerprint

		firstDetectedTime :=
			activeReport.Status.FirstDetectedAt.Time

		lastObservedTime :=
			activeReport.Status.LastObservedAt.Time

		restartCount :=
			activeReport.Status.Evidence.RestartCount

		// -------------------------------------------------------------
		// STEP 4:
		// Simulate recovery.
		//
		// The same container is now Running instead of
		// CrashLoopBackOff.
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

		// -------------------------------------------------------------
		// STEP 5:
		// Reconcile after recovery.
		// -------------------------------------------------------------

		updatedPolicy :=
			reconcilePolicy(
				policy.Name,
			)

		// Policy should now say no incident is detected.
		incidentCondition :=
			apimeta.FindStatusCondition(
				updatedPolicy.Status.Conditions,
				conditionTypeIncidentDetected,
			)

		Expect(
			incidentCondition,
		).NotTo(BeNil())

		Expect(
			incidentCondition.Status,
		).To(Equal(metav1.ConditionFalse))

		Expect(
			incidentCondition.Reason,
		).To(Equal("NoIncidentDetected"))

		// -------------------------------------------------------------
		// STEP 6:
		// The report must still exist.
		// -------------------------------------------------------------

		resolvedReports :=
			&opsv1alpha1.IncidentReportList{}

		Expect(
			k8sClient.List(
				ctx,
				resolvedReports,

				client.InNamespace(
					controllerTestNamespace,
				),

				client.MatchingLabels{
					reportPolicyUIDLabel: string(policy.UID),
				},
			),
		).To(Succeed())

		// We retain incident history.
		Expect(
			resolvedReports.Items,
		).To(HaveLen(1))

		resolvedReport :=
			&resolvedReports.Items[0]

		// -------------------------------------------------------------
		// STEP 7:
		// Verify same report identity.
		// -------------------------------------------------------------

		Expect(
			resolvedReport.Name,
		).To(Equal(reportName))

		Expect(
			resolvedReport.Spec.Fingerprint,
		).To(Equal(fingerprint))

		// -------------------------------------------------------------
		// STEP 8:
		// Verify lifecycle transition.
		// -------------------------------------------------------------

		Expect(
			resolvedReport.Status.Phase,
		).To(Equal("Resolved"))

		Expect(
			resolvedReport.Status.ResolvedAt,
		).NotTo(BeNil())

		// -------------------------------------------------------------
		// STEP 9:
		// Historical data must remain unchanged.
		// -------------------------------------------------------------

		Expect(
			resolvedReport.Status.FirstDetectedAt,
		).NotTo(BeNil())

		Expect(
			resolvedReport.Status.FirstDetectedAt.Time.Equal(
				firstDetectedTime,
			),
		).To(BeTrue())

		Expect(
			resolvedReport.Status.LastObservedAt,
		).NotTo(BeNil())

		Expect(
			resolvedReport.Status.LastObservedAt.Time.Equal(
				lastObservedTime,
			),
		).To(BeTrue())

		// Evidence from the incident should also be preserved.
		Expect(
			resolvedReport.Status.Evidence.RestartCount,
		).To(Equal(restartCount))

		Expect(
			resolvedReport.Status.Evidence.WaitingReason,
		).To(Equal("CrashLoopBackOff"))
	})
})

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

	It("creates one Active IncidentReport and reuses it for repeated observations", func() {

		// -----------------------------------------------------------------
		// STEP 1:
		// Create a Pod that is currently in CrashLoopBackOff.
		// -----------------------------------------------------------------

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

		// envtest does not run kubelet, so we simulate the container status.
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

		// -----------------------------------------------------------------
		// STEP 2:
		// Create a policy that monitors this Pod.
		// -----------------------------------------------------------------

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

		// -----------------------------------------------------------------
		// STEP 3:
		// First reconciliation.
		//
		// Expected:
		// - CrashLoop detected
		// - IncidentReport created
		// - IncidentReport phase = Active
		// -----------------------------------------------------------------

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

		// -----------------------------------------------------------------
		// STEP 4:
		// List reports belonging to this policy.
		// -----------------------------------------------------------------

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

		// There must be exactly one report.
		Expect(
			firstReports.Items,
		).To(HaveLen(1))

		firstReport := &firstReports.Items[0]

		// -----------------------------------------------------------------
		// STEP 5:
		// Verify stable incident identity.
		// -----------------------------------------------------------------

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

		// -----------------------------------------------------------------
		// STEP 6:
		// Verify lifecycle state.
		// -----------------------------------------------------------------

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

		// -----------------------------------------------------------------
		// STEP 7:
		// Verify evidence.
		// -----------------------------------------------------------------

		Expect(
			firstReport.Status.Evidence.RestartCount,
		).To(Equal(int32(3)))

		Expect(
			firstReport.Status.Evidence.CurrentState,
		).To(Equal("Waiting"))

		Expect(
			firstReport.Status.Evidence.WaitingReason,
		).To(Equal("CrashLoopBackOff"))

		// -----------------------------------------------------------------
		// STEP 8:
		// Simulate the same incident continuing.
		//
		// RestartCount increases, but this is still:
		//
		// same policy
		// same Pod
		// same container
		// same incident type
		//
		// Therefore it must remain the same IncidentReport.
		// -----------------------------------------------------------------

		pod.Status.ContainerStatuses[0].RestartCount = 4

		Expect(
			k8sClient.Status().Update(
				ctx,
				pod,
			),
		).To(Succeed())

		// -----------------------------------------------------------------
		// STEP 9:
		// Reconcile the policy again.
		// -----------------------------------------------------------------

		reconcilePolicy(
			policy.Name,
		)

		// -----------------------------------------------------------------
		// STEP 10:
		// List IncidentReports again.
		// -----------------------------------------------------------------

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

		// Critical duplicate-prevention check.
		Expect(
			secondReports.Items,
		).To(HaveLen(1))

		secondReport :=
			&secondReports.Items[0]

		// -----------------------------------------------------------------
		// STEP 11:
		// Verify this is exactly the same report.
		// -----------------------------------------------------------------

		Expect(
			secondReport.Name,
		).To(Equal(firstReportName))

		Expect(
			secondReport.Spec.Fingerprint,
		).To(Equal(firstFingerprint))

		Expect(
			secondReport.Status.Phase,
		).To(Equal("Active"))

		// -----------------------------------------------------------------
		// STEP 12:
		// FirstDetectedAt must remain unchanged.
		// -----------------------------------------------------------------

		Expect(
			secondReport.Status.FirstDetectedAt,
		).NotTo(BeNil())

		Expect(
			secondReport.Status.FirstDetectedAt.Time.Equal(
				firstDetectedTime,
			),
		).To(BeTrue())

		// -----------------------------------------------------------------
		// STEP 13:
		// LastObservedAt must not move backward.
		// -----------------------------------------------------------------

		Expect(
			secondReport.Status.LastObservedAt,
		).NotTo(BeNil())

		Expect(
			secondReport.Status.LastObservedAt.Time.Before(
				firstObservedTime,
			),
		).To(BeFalse())

		// -----------------------------------------------------------------
		// STEP 14:
		// Evidence should refresh.
		// -----------------------------------------------------------------

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
})

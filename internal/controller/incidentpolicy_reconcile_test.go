package controller

import (
	"time"

	opsv1alpha1 "github.com/yashshrivastav22/kubetriage/api/v1alpha1"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	ctrl "sigs.k8s.io/controller-runtime"
)

const controllerTestNamespace = "kubetriage-controller-test"

var _ = Describe("IncidentPolicy reconciliation", func() {

	BeforeEach(func() {
		namespace := &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name: controllerTestNamespace,
			},
		}

		err := k8sClient.Create(ctx, namespace)

		if err != nil && !apierrors.IsAlreadyExists(err) {
			Expect(err).NotTo(HaveOccurred())
		}
	})

	It("reports Unknown when no Pods match the selector", func() {

		policy := &opsv1alpha1.IncidentPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "no-matching-pods",
				Namespace: controllerTestNamespace,
			},

			Spec: opsv1alpha1.IncidentPolicySpec{
				Selector: metav1.LabelSelector{
					MatchLabels: map[string]string{
						"app": "missing-app",
					},
				},

				Checks: opsv1alpha1.IncidentChecks{
					CrashLoop: true,
				},
			},
		}

		Expect(
			k8sClient.Create(ctx, policy),
		).To(Succeed())

		reconciler := &IncidentPolicyReconciler{
			Client: k8sClient,
		}

		result, err := reconciler.Reconcile(
			ctx,
			ctrl.Request{
				NamespacedName: types.NamespacedName{
					Name:      policy.Name,
					Namespace: policy.Namespace,
				},
			},
		)

		Expect(err).NotTo(HaveOccurred())
		Expect(result.RequeueAfter).To(Equal(30 * time.Second))

		updated := &opsv1alpha1.IncidentPolicy{}

		Expect(
			k8sClient.Get(
				ctx,
				types.NamespacedName{
					Name:      policy.Name,
					Namespace: policy.Namespace,
				},
				updated,
			),
		).To(Succeed())

		Expect(updated.Status.MonitoredPods).To(Equal(int32(0)))
		Expect(
			updated.Status.ObservedGeneration,
		).To(Equal(updated.Generation))

		condition := apimeta.FindStatusCondition(
			updated.Status.Conditions,
			conditionTypeIncidentDetected,
		)

		Expect(condition).NotTo(BeNil())
		Expect(condition.Status).To(Equal(metav1.ConditionUnknown))
		Expect(condition.Reason).To(Equal("NoMatchingPods"))
	})

	It("counts only matching Pods and reports no incident", func() {

		createTestPod(
			"checkout-healthy",
			map[string]string{
				"app": "checkout-healthy-test",
			},
			corev1.ContainerState{
				Running: &corev1.ContainerStateRunning{},
			},
		)

		// This Pod is crashing, but it has a different label.
		// KubeTriage must ignore it.
		createTestPod(
			"payment-crashing",
			map[string]string{
				"app": "payment",
			},
			corev1.ContainerState{
				Waiting: &corev1.ContainerStateWaiting{
					Reason:  "CrashLoopBackOff",
					Message: "back-off restarting failed container",
				},
			},
		)

		policy := &opsv1alpha1.IncidentPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "healthy-policy",
				Namespace: controllerTestNamespace,
			},

			Spec: opsv1alpha1.IncidentPolicySpec{
				Selector: metav1.LabelSelector{
					MatchLabels: map[string]string{
						"app": "checkout-healthy-test",
					},
				},

				Checks: opsv1alpha1.IncidentChecks{
					CrashLoop: true,
				},
			},
		}

		Expect(
			k8sClient.Create(ctx, policy),
		).To(Succeed())

		updated := reconcilePolicy(policy.Name)

		Expect(updated.Status.MonitoredPods).To(Equal(int32(1)))

		condition := apimeta.FindStatusCondition(
			updated.Status.Conditions,
			conditionTypeIncidentDetected,
		)

		Expect(condition).NotTo(BeNil())
		Expect(condition.Status).To(Equal(metav1.ConditionFalse))
		Expect(condition.Reason).To(Equal("NoIncidentDetected"))
	})

	It("detects CrashLoopBackOff in a matching Pod", func() {

		createTestPod(
			"checkout-crashing",
			map[string]string{
				"app": "checkout-crash-test",
			},
			corev1.ContainerState{
				Waiting: &corev1.ContainerStateWaiting{
					Reason:  "CrashLoopBackOff",
					Message: "back-off restarting failed container",
				},
			},
		)

		policy := &opsv1alpha1.IncidentPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "crash-policy",
				Namespace: controllerTestNamespace,
			},

			Spec: opsv1alpha1.IncidentPolicySpec{
				Selector: metav1.LabelSelector{
					MatchLabels: map[string]string{
						"app": "checkout-crash-test",
					},
				},

				Checks: opsv1alpha1.IncidentChecks{
					CrashLoop: true,
				},
			},
		}

		Expect(
			k8sClient.Create(ctx, policy),
		).To(Succeed())

		updated := reconcilePolicy(policy.Name)

		Expect(updated.Status.MonitoredPods).To(Equal(int32(1)))

		condition := apimeta.FindStatusCondition(
			updated.Status.Conditions,
			conditionTypeIncidentDetected,
		)

		Expect(condition).NotTo(BeNil())
		Expect(condition.Status).To(Equal(metav1.ConditionTrue))
		Expect(condition.Reason).To(
			Equal("CrashLoopBackOffDetected"),
		)

		Expect(condition.Message).To(
			ContainSubstring("checkout-crashing"),
		)

		Expect(condition.Message).To(
			ContainSubstring("app"),
		)
	})

	It("reports partial evaluation for checks not implemented yet", func() {

		createTestPod(
			"unsupported-check-pod",
			map[string]string{
				"app": "unsupported-check-test",
			},
			corev1.ContainerState{
				Running: &corev1.ContainerStateRunning{},
			},
		)

		policy := &opsv1alpha1.IncidentPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "unsupported-policy",
				Namespace: controllerTestNamespace,
			},

			Spec: opsv1alpha1.IncidentPolicySpec{
				Selector: metav1.LabelSelector{
					MatchLabels: map[string]string{
						"app": "unsupported-check-test",
					},
				},

				Checks: opsv1alpha1.IncidentChecks{
					OOMKilled: true,
				},
			},
		}

		Expect(
			k8sClient.Create(ctx, policy),
		).To(Succeed())

		updated := reconcilePolicy(policy.Name)

		ready := apimeta.FindStatusCondition(
			updated.Status.Conditions,
			conditionTypeReady,
		)

		Expect(ready).NotTo(BeNil())
		Expect(ready.Status).To(Equal(metav1.ConditionFalse))
		Expect(ready.Reason).To(Equal("UnsupportedChecks"))

		incident := apimeta.FindStatusCondition(
			updated.Status.Conditions,
			conditionTypeIncidentDetected,
		)

		Expect(incident).NotTo(BeNil())
		Expect(incident.Status).To(Equal(metav1.ConditionUnknown))
		Expect(incident.Reason).To(Equal("PartialEvaluation"))
	})
})

// createTestPod creates a Pod through the envtest API server and then
// simulates the container state that kubelet would normally publish.
func createTestPod(
	name string,
	labels map[string]string,
	containerState corev1.ContainerState,
) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: controllerTestNamespace,
			Labels:    labels,
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
		k8sClient.Create(ctx, pod),
	).To(Succeed())

	pod.Status.ContainerStatuses = []corev1.ContainerStatus{
		{
			Name:  "app",
			State: containerState,
		},
	}

	Expect(
		k8sClient.Status().Update(ctx, pod),
	).To(Succeed())
}

// reconcilePolicy invokes the real Reconcile function and then retrieves
// the resulting IncidentPolicy from the API server.
func reconcilePolicy(
	policyName string,
) *opsv1alpha1.IncidentPolicy {
	reconciler := &IncidentPolicyReconciler{
		Client: k8sClient,
	}

	result, err := reconciler.Reconcile(
		ctx,
		ctrl.Request{
			NamespacedName: types.NamespacedName{
				Name:      policyName,
				Namespace: controllerTestNamespace,
			},
		},
	)

	Expect(err).NotTo(HaveOccurred())
	Expect(result.RequeueAfter).To(Equal(30 * time.Second))

	updated := &opsv1alpha1.IncidentPolicy{}

	Expect(
		k8sClient.Get(
			ctx,
			types.NamespacedName{
				Name:      policyName,
				Namespace: controllerTestNamespace,
			},
			updated,
		),
	).To(Succeed())

	return updated
}

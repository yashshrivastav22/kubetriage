package controller

import (
	"context"

	opsv1alpha1 "github.com/yashshrivastav22/kubetriage/api/v1alpha1"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

const mappingTestNamespace = "kubetriage-mapping-test"

var _ = Describe("Pod to IncidentPolicy mapping", func() {

	BeforeEach(func() {
		namespace := &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name: mappingTestNamespace,
			},
		}

		err := k8sClient.Create(ctx, namespace)

		if err != nil && !apierrors.IsAlreadyExists(err) {
			Expect(err).NotTo(HaveOccurred())
		}
	})

	AfterEach(func() {
		policies := &opsv1alpha1.IncidentPolicyList{}

		Expect(
			k8sClient.List(
				ctx,
				policies,
				client.InNamespace(mappingTestNamespace),
			),
		).To(Succeed())

		for i := range policies.Items {
			Expect(
				k8sClient.Delete(
					ctx,
					&policies.Items[i],
				),
			).To(Succeed())
		}
	})

	It("enqueues every policy whose selector matches the Pod", func() {

		createMappingPolicy(
			"checkout-policy",
			map[string]string{
				"app": "checkout",
			},
		)

		createMappingPolicy(
			"frontend-policy",
			map[string]string{
				"tier": "frontend",
			},
		)

		createMappingPolicy(
			"payment-policy",
			map[string]string{
				"app": "payment",
			},
		)

		pod := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "checkout-abc123",
				Namespace: mappingTestNamespace,
				Labels: map[string]string{
					"app":  "checkout",
					"tier": "frontend",
				},
			},
		}

		reconciler := &IncidentPolicyReconciler{
			Client: k8sClient,
		}

		requests := reconciler.mapPodToIncidentPolicies(
			context.Background(),
			pod,
		)

		Expect(requests).To(
			ConsistOf(
				reconcile.Request{
					NamespacedName: types.NamespacedName{
						Name:      "checkout-policy",
						Namespace: mappingTestNamespace,
					},
				},
				reconcile.Request{
					NamespacedName: types.NamespacedName{
						Name:      "frontend-policy",
						Namespace: mappingTestNamespace,
					},
				},
			),
		)
	})

	It("does not enqueue policies whose selectors do not match", func() {

		createMappingPolicy(
			"payment-policy",
			map[string]string{
				"app": "payment",
			},
		)

		pod := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "checkout-xyz",
				Namespace: mappingTestNamespace,
				Labels: map[string]string{
					"app": "checkout",
				},
			},
		}

		reconciler := &IncidentPolicyReconciler{
			Client: k8sClient,
		}

		requests := reconciler.mapPodToIncidentPolicies(
			ctx,
			pod,
		)

		Expect(requests).To(BeEmpty())
	})

	It("does not enqueue policies from another namespace", func() {

		otherNamespace := &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name: "kubetriage-other-mapping-test",
			},
		}

		err := k8sClient.Create(ctx, otherNamespace)

		if err != nil && !apierrors.IsAlreadyExists(err) {
			Expect(err).NotTo(HaveOccurred())
		}

		policy := &opsv1alpha1.IncidentPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "other-namespace-policy",
				Namespace: otherNamespace.Name,
			},
			Spec: opsv1alpha1.IncidentPolicySpec{
				Selector: metav1.LabelSelector{
					MatchLabels: map[string]string{
						"app": "checkout",
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

		DeferCleanup(func() {
			Expect(
				client.IgnoreNotFound(
					k8sClient.Delete(ctx, policy),
				),
			).To(Succeed())
		})

		pod := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "checkout-local",
				Namespace: mappingTestNamespace,
				Labels: map[string]string{
					"app": "checkout",
				},
			},
		}

		reconciler := &IncidentPolicyReconciler{
			Client: k8sClient,
		}

		requests := reconciler.mapPodToIncidentPolicies(
			ctx,
			pod,
		)

		Expect(requests).To(BeEmpty())
	})

	It("ignores objects that are not Pods", func() {

		reconciler := &IncidentPolicyReconciler{
			Client: k8sClient,
		}

		configMap := &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "not-a-pod",
				Namespace: mappingTestNamespace,
			},
		}

		requests := reconciler.mapPodToIncidentPolicies(
			ctx,
			configMap,
		)

		Expect(requests).To(BeEmpty())
	})
})

func createMappingPolicy(
	name string,
	matchLabels map[string]string,
) {
	policy := &opsv1alpha1.IncidentPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: mappingTestNamespace,
		},

		Spec: opsv1alpha1.IncidentPolicySpec{
			Selector: metav1.LabelSelector{
				MatchLabels: matchLabels,
			},

			Checks: opsv1alpha1.IncidentChecks{
				CrashLoop: true,
			},
		},
	}

	Expect(
		k8sClient.Create(ctx, policy),
	).To(Succeed())
}

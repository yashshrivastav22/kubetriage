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
	opsv1alpha1 "github.com/yashshrivastav22/kubetriage/api/v1alpha1"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

const apiTestNamespace = "kubetriage-api-test"

var _ = Describe("IncidentPolicy API validation", func() {

	BeforeEach(func() {
		namespace := &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name: apiTestNamespace,
			},
		}

		err := k8sClient.Create(ctx, namespace)

		if err != nil && !apierrors.IsAlreadyExists(err) {
			Expect(err).NotTo(HaveOccurred())
		}
	})

	AfterEach(func() {
		policies := &opsv1alpha1.IncidentPolicyList{}

		err := k8sClient.List(
			ctx,
			policies,
			client.InNamespace(apiTestNamespace),
		)

		Expect(err).NotTo(HaveOccurred())

		for i := range policies.Items {
			policy := &policies.Items[i]

			Expect(
				k8sClient.Delete(ctx, policy),
			).To(Succeed())
		}
	})

	Context("when creating an IncidentPolicy", func() {

		It("accepts a valid policy", func() {

			policy := &opsv1alpha1.IncidentPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "valid-policy",
					Namespace: apiTestNamespace,
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
		})

		It("rejects an empty selector", func() {

			policy := &opsv1alpha1.IncidentPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "empty-selector",
					Namespace: apiTestNamespace,
				},

				Spec: opsv1alpha1.IncidentPolicySpec{
					Selector: metav1.LabelSelector{},

					Checks: opsv1alpha1.IncidentChecks{
						CrashLoop: true,
					},
				},
			}

			err := k8sClient.Create(ctx, policy)

			Expect(err).To(HaveOccurred())

			Expect(
				apierrors.IsInvalid(err),
			).To(BeTrue())
		})

		It("rejects a policy with no incident checks enabled", func() {

			policy := &opsv1alpha1.IncidentPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "no-checks",
					Namespace: apiTestNamespace,
				},

				Spec: opsv1alpha1.IncidentPolicySpec{
					Selector: metav1.LabelSelector{
						MatchLabels: map[string]string{
							"app": "checkout",
						},
					},

					Checks: opsv1alpha1.IncidentChecks{},
				},
			}

			err := k8sClient.Create(ctx, policy)

			Expect(err).To(HaveOccurred())

			Expect(
				apierrors.IsInvalid(err),
			).To(BeTrue())
		})
	})
})

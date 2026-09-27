package controller

import (
	"fmt"
	"time"

	opsv1alpha1 "github.com/yashshrivastav22/kubetriage/api/v1alpha1"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"

	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

var _ = Describe("IncidentPolicy scale validation", func() {
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

		if err != nil && !apierrors.IsAlreadyExists(err) {
			Expect(err).NotTo(HaveOccurred())
		}
	})

	It("evaluates 100 matching Pods and creates reports only for failing Pods", func() {
		const (
			totalPods   = 100
			failingPods = 10
		)

		policy := &opsv1alpha1.IncidentPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "scale-validation-policy",
				Namespace: controllerTestNamespace,
			},
			Spec: opsv1alpha1.IncidentPolicySpec{
				Selector: metav1.LabelSelector{
					MatchLabels: map[string]string{
						"app": "kubetriage-scale-test",
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

		for i := 0; i < totalPods; i++ {
			pod := &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name: fmt.Sprintf(
						"scale-validation-pod-%03d",
						i,
					),
					Namespace: controllerTestNamespace,
					Labels: map[string]string{
						"app": "kubetriage-scale-test",
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

			pod.Status.Phase =
				corev1.PodRunning

			if i < failingPods {
				pod.Status.ContainerStatuses =
					[]corev1.ContainerStatus{
						{
							Name:         "app",
							Image:        "busybox:1.36",
							RestartCount: 5,
							State: corev1.ContainerState{
								Waiting: &corev1.ContainerStateWaiting{
									Reason:  "CrashLoopBackOff",
									Message: "back-off restarting failed container",
								},
							},
							LastTerminationState: corev1.ContainerState{
								Terminated: &corev1.ContainerStateTerminated{
									ExitCode: 1,
									Reason:   "Error",
								},
							},
						},
					}
			} else {
				pod.Status.ContainerStatuses =
					[]corev1.ContainerStatus{
						{
							Name:         "app",
							Image:        "busybox:1.36",
							RestartCount: 0,
							State: corev1.ContainerState{
								Running: &corev1.ContainerStateRunning{
									StartedAt: metav1.Now(),
								},
							},
						},
					}
			}

			Expect(
				k8sClient.Status().Update(
					ctx,
					pod,
				),
			).To(Succeed())
		}

		testScheme :=
			runtime.NewScheme()

		Expect(
			clientgoscheme.AddToScheme(
				testScheme,
			),
		).To(Succeed())

		Expect(
			opsv1alpha1.AddToScheme(
				testScheme,
			),
		).To(Succeed())

		reconciler :=
			&IncidentPolicyReconciler{
				Client: k8sClient,

				Scheme: testScheme,
			}

		request :=
			ctrl.Request{
				NamespacedName: types.NamespacedName{
					Name: policy.Name,

					Namespace: policy.Namespace,
				},
			}

		started :=
			time.Now()

		_, err :=
			reconciler.Reconcile(
				ctx,
				request,
			)

		Expect(err).NotTo(HaveOccurred())

		elapsed :=
			time.Since(started)

		GinkgoWriter.Printf(
			"scale validation: reconciled %d Pods with %d failures in %s\n",
			totalPods,
			failingPods,
			elapsed,
		)

		updatedPolicy :=
			&opsv1alpha1.IncidentPolicy{}

		Expect(
			k8sClient.Get(
				ctx,
				types.NamespacedName{
					Name: policy.Name,

					Namespace: policy.Namespace,
				},
				updatedPolicy,
			),
		).To(Succeed())

		Expect(
			updatedPolicy.Status.MonitoredPods,
		).To(Equal(
			int32(totalPods),
		))

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

		Expect(
			reports.Items,
		).To(HaveLen(
			failingPods,
		))

		fingerprints :=
			make(map[string]struct{})

		for i := range reports.Items {
			report :=
				&reports.Items[i]

			Expect(
				string(report.Status.Phase),
			).To(Equal(
				"Active",
			))

			Expect(
				string(report.Spec.IncidentType),
			).To(Equal(
				"CrashLoopBackOff",
			))

			fingerprints[report.Spec.Fingerprint] =
				struct{}{}
		}

		Expect(
			fingerprints,
		).To(HaveLen(
			failingPods,
		))

		// Reconcile again and verify idempotency.
		_, err =
			reconciler.Reconcile(
				ctx,
				request,
			)

		Expect(err).NotTo(HaveOccurred())

		reportsAfterSecondReconcile :=
			&opsv1alpha1.IncidentReportList{}

		Expect(
			k8sClient.List(
				ctx,
				reportsAfterSecondReconcile,
				client.InNamespace(
					controllerTestNamespace,
				),
				client.MatchingLabels{
					reportPolicyUIDLabel: string(policy.UID),
				},
			),
		).To(Succeed())

		Expect(
			reportsAfterSecondReconcile.Items,
		).To(HaveLen(
			failingPods,
		))
	})

	It("handles CrashLoopBackOff, OOMKilled, and ImagePull incidents simultaneously", func() {
		const (
			crashLoopPods = 10
			oomPods       = 10
			imagePullPods = 10
			totalPods     = crashLoopPods + oomPods + imagePullPods
		)

		// -----------------------------------------------------------------
		// One policy enables all three detectors.
		// -----------------------------------------------------------------

		policy := &opsv1alpha1.IncidentPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "mixed-scale-policy",
				Namespace: controllerTestNamespace,
			},
			Spec: opsv1alpha1.IncidentPolicySpec{
				Selector: metav1.LabelSelector{
					MatchLabels: map[string]string{
						"app": "kubetriage-mixed-scale",
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

		// -----------------------------------------------------------------
		// 10 CrashLoopBackOff Pods.
		// -----------------------------------------------------------------

		for i := 0; i < crashLoopPods; i++ {
			pod := newMixedScalePod(
				fmt.Sprintf(
					"mixed-crashloop-%02d",
					i,
				),
			)

			Expect(
				k8sClient.Create(
					ctx,
					pod,
				),
			).To(Succeed())

			pod.Status.Phase =
				corev1.PodRunning

			pod.Status.ContainerStatuses =
				[]corev1.ContainerStatus{
					{
						Name: "app",

						Image: "busybox:1.36",

						RestartCount: 5,

						State: corev1.ContainerState{
							Waiting: &corev1.ContainerStateWaiting{
								Reason: "CrashLoopBackOff",

								Message: "back-off restarting failed container",
							},
						},

						LastTerminationState: corev1.ContainerState{
							Terminated: &corev1.ContainerStateTerminated{
								ExitCode: 1,

								Reason: "Error",
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
		}

		// -----------------------------------------------------------------
		// 10 OOMKilled Pods.
		// -----------------------------------------------------------------

		for i := 0; i < oomPods; i++ {
			pod := newMixedScalePod(
				fmt.Sprintf(
					"mixed-oom-%02d",
					i,
				),
			)

			Expect(
				k8sClient.Create(
					ctx,
					pod,
				),
			).To(Succeed())

			pod.Status.Phase =
				corev1.PodRunning

			pod.Status.ContainerStatuses =
				[]corev1.ContainerStatus{
					{
						Name: "app",

						Image: "busybox:1.36",

						RestartCount: 1,

						State: corev1.ContainerState{
							Running: &corev1.ContainerStateRunning{
								StartedAt: metav1.Now(),
							},
						},

						LastTerminationState: corev1.ContainerState{
							Terminated: &corev1.ContainerStateTerminated{
								ExitCode: 137,

								Reason: "OOMKilled",
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
		}

		// -----------------------------------------------------------------
		// 10 ImagePullBackOff Pods.
		// -----------------------------------------------------------------

		for i := 0; i < imagePullPods; i++ {
			pod := newMixedScalePod(
				fmt.Sprintf(
					"mixed-imagepull-%02d",
					i,
				),
			)

			Expect(
				k8sClient.Create(
					ctx,
					pod,
				),
			).To(Succeed())

			pod.Status.Phase =
				corev1.PodPending

			pod.Status.ContainerStatuses =
				[]corev1.ContainerStatus{
					{
						Name: "app",

						Image: "registry.example.invalid/missing:v1",

						RestartCount: 0,

						State: corev1.ContainerState{
							Waiting: &corev1.ContainerStateWaiting{
								Reason: "ImagePullBackOff",

								Message: "back-off pulling image",
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
		}

		testScheme :=
			runtime.NewScheme()

		Expect(
			clientgoscheme.AddToScheme(
				testScheme,
			),
		).To(Succeed())

		Expect(
			opsv1alpha1.AddToScheme(
				testScheme,
			),
		).To(Succeed())

		reconciler :=
			&IncidentPolicyReconciler{
				Client: k8sClient,

				Scheme: testScheme,
			}

		request :=
			ctrl.Request{
				NamespacedName: types.NamespacedName{
					Name: policy.Name,

					Namespace: policy.Namespace,
				},
			}

		started :=
			time.Now()

		_, err :=
			reconciler.Reconcile(
				ctx,
				request,
			)

		Expect(err).NotTo(HaveOccurred())

		GinkgoWriter.Printf(
			"mixed incident validation: reconciled %d failing Pods in %s\n",
			totalPods,
			time.Since(started),
		)

		// -----------------------------------------------------------------
		// Verify all matching Pods were evaluated.
		// -----------------------------------------------------------------

		updatedPolicy :=
			&opsv1alpha1.IncidentPolicy{}

		Expect(
			k8sClient.Get(
				ctx,
				types.NamespacedName{
					Name: policy.Name,

					Namespace: policy.Namespace,
				},
				updatedPolicy,
			),
		).To(Succeed())

		Expect(
			updatedPolicy.Status.MonitoredPods,
		).To(Equal(
			int32(totalPods),
		))

		// -----------------------------------------------------------------
		// Verify exactly 30 reports.
		// -----------------------------------------------------------------

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

		Expect(
			reports.Items,
		).To(HaveLen(
			totalPods,
		))

		typeCounts :=
			map[string]int{}

		fingerprints :=
			map[string]struct{}{}

		for i := range reports.Items {
			report :=
				&reports.Items[i]

			Expect(
				string(report.Status.Phase),
			).To(Equal(
				"Active",
			))

			incidentType :=
				string(
					report.Spec.IncidentType,
				)

			typeCounts[incidentType]++

			fingerprints[report.Spec.Fingerprint] =
				struct{}{}
		}

		Expect(
			typeCounts["CrashLoopBackOff"],
		).To(Equal(
			crashLoopPods,
		))

		Expect(
			typeCounts["OOMKilled"],
		).To(Equal(
			oomPods,
		))

		Expect(
			typeCounts["ImagePullBackOff"],
		).To(Equal(
			imagePullPods,
		))

		Expect(
			fingerprints,
		).To(HaveLen(
			totalPods,
		))

		// -----------------------------------------------------------------
		// Reconcile again.
		//
		// Even with three simultaneous incident classes, no duplicate
		// IncidentReports may be created.
		// -----------------------------------------------------------------

		_, err =
			reconciler.Reconcile(
				ctx,
				request,
			)

		Expect(err).NotTo(HaveOccurred())

		reportsAfterSecondReconcile :=
			&opsv1alpha1.IncidentReportList{}

		Expect(
			k8sClient.List(
				ctx,
				reportsAfterSecondReconcile,
				client.InNamespace(
					controllerTestNamespace,
				),
				client.MatchingLabels{
					reportPolicyUIDLabel: string(policy.UID),
				},
			),
		).To(Succeed())

		Expect(
			reportsAfterSecondReconcile.Items,
		).To(HaveLen(
			totalPods,
		))
	})
})

func newMixedScalePod(
	name string,
) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,

			Namespace: controllerTestNamespace,

			Labels: map[string]string{
				"app": "kubetriage-mixed-scale",
			},
		},

		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{
					Name: "app",

					Image: "busybox:1.36",
				},
			},
		},
	}
}

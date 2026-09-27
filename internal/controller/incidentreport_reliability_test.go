package controller

import (
	"context"
	"errors"
	"strings"

	opsv1alpha1 "github.com/yashshrivastav22/kubetriage/api/v1alpha1"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

var incidentReportGroupResource = schema.GroupResource{
	Group:    "ops.kubetriage.dev",
	Resource: "incidentreports",
}

// -----------------------------------------------------------------------------
// Client used to simulate this race:
//
// Reconcile A                         Reconcile B
//     GET -> NotFound                    |
//                                        CREATE report
//     CREATE -> AlreadyExists <----------+
//     GET existing report
//     continue normally
// -----------------------------------------------------------------------------

type incidentReportCreateRaceClient struct {
	client.Client

	targetNamespace string
	targetName      string

	forcedNotFound bool
	injectedRace   bool
}

func (c *incidentReportCreateRaceClient) Get(
	ctx context.Context,
	key client.ObjectKey,
	obj client.Object,
	opts ...client.GetOption,
) error {
	_, isIncidentReport := obj.(*opsv1alpha1.IncidentReport)

	if isIncidentReport &&
		key.Namespace == c.targetNamespace &&
		key.Name == c.targetName &&
		!c.forcedNotFound {

		c.forcedNotFound = true

		return apierrors.NewNotFound(
			incidentReportGroupResource,
			key.Name,
		)
	}

	return c.Client.Get(
		ctx,
		key,
		obj,
		opts...,
	)
}

func (c *incidentReportCreateRaceClient) Create(
	ctx context.Context,
	obj client.Object,
	opts ...client.CreateOption,
) error {
	report, isIncidentReport :=
		obj.(*opsv1alpha1.IncidentReport)

	if isIncidentReport &&
		report.Namespace == c.targetNamespace &&
		report.Name == c.targetName &&
		!c.injectedRace {

		c.injectedRace = true

		// Simulate another reconciler winning the CREATE race.
		winningReport := report.DeepCopy()

		if err := c.Client.Create(
			ctx,
			winningReport,
			opts...,
		); err != nil {
			return err
		}

		// Our reconciler now sees what a real losing CREATE would see.
		return apierrors.NewAlreadyExists(
			incidentReportGroupResource,
			report.Name,
		)
	}

	return c.Client.Create(
		ctx,
		obj,
		opts...,
	)
}

// -----------------------------------------------------------------------------
// Client used to simulate a transient Kubernetes API failure during GET.
// -----------------------------------------------------------------------------

type incidentReportGetErrorClient struct {
	client.Client

	targetNamespace string
	targetName      string
	injectedError   error
}

func (c *incidentReportGetErrorClient) Get(
	ctx context.Context,
	key client.ObjectKey,
	obj client.Object,
	opts ...client.GetOption,
) error {
	_, isIncidentReport := obj.(*opsv1alpha1.IncidentReport)

	if isIncidentReport &&
		key.Namespace == c.targetNamespace &&
		key.Name == c.targetName {

		return c.injectedError
	}

	return c.Client.Get(
		ctx,
		key,
		obj,
		opts...,
	)
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

var _ = Describe("IncidentReport reliability", func() {
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

	It("recovers when another reconcile creates the IncidentReport first", func() {
		pod := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "report-create-race-pod",
				Namespace: controllerTestNamespace,
			},
			Spec: corev1.PodSpec{
				NodeName: "worker-race-test",
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
					Image:        "busybox:1.36",
					RestartCount: 3,
					State: corev1.ContainerState{
						Waiting: &corev1.ContainerStateWaiting{
							Reason: "CrashLoopBackOff",
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

		Expect(
			k8sClient.Status().Update(
				ctx,
				pod,
			),
		).To(Succeed())

		policy := &opsv1alpha1.IncidentPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "report-create-race-policy",
				Namespace: controllerTestNamespace,
			},
			Spec: opsv1alpha1.IncidentPolicySpec{
				Selector: metav1.LabelSelector{
					MatchLabels: map[string]string{
						"app": "race-test",
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

		finding := &incidentFinding{
			PodName:               pod.Name,
			PodUID:                string(pod.UID),
			ContainerName:         "app",
			IncidentType:          "CrashLoopBackOff",
			Message:               "container is repeatedly restarting",
			RestartCount:          3,
			CurrentState:          "Waiting",
			WaitingReason:         "CrashLoopBackOff",
			LastTerminationReason: "Error",
		}

		fingerprint := strings.Repeat(
			"a",
			64,
		)

		reportName :=
			incidentReportName(
				fingerprint,
			)

		raceClient :=
			&incidentReportCreateRaceClient{
				Client:          k8sClient,
				targetNamespace: controllerTestNamespace,
				targetName:      reportName,
			}

		reconciler :=
			&IncidentPolicyReconciler{
				Client: raceClient,
			}

		err := reconciler.ensureIncidentReport(
			ctx,
			policy,
			finding,
			fingerprint,
		)

		Expect(err).NotTo(HaveOccurred())

		Expect(
			raceClient.forcedNotFound,
		).To(BeTrue())

		Expect(
			raceClient.injectedRace,
		).To(BeTrue())

		report :=
			&opsv1alpha1.IncidentReport{}

		Expect(
			k8sClient.Get(
				ctx,
				client.ObjectKey{
					Name:      reportName,
					Namespace: controllerTestNamespace,
				},
				report,
			),
		).To(Succeed())

		Expect(
			report.Spec.Fingerprint,
		).To(Equal(fingerprint))

		Expect(
			report.Spec.PodName,
		).To(Equal(pod.Name))

		Expect(
			report.Spec.ContainerName,
		).To(Equal("app"))

		Expect(
			report.Spec.IncidentType,
		).To(Equal("CrashLoopBackOff"))

		// Most importantly, the losing reconciler continued and
		// successfully updated the existing report.
		Expect(
			report.Status.Phase,
		).To(Equal("Active"))

		Expect(
			report.Status.FirstDetectedAt,
		).NotTo(BeNil())

		Expect(
			report.Status.LastObservedAt,
		).NotTo(BeNil())
	})

	It("rejects a deterministic report-name collision", func() {
		policy := &opsv1alpha1.IncidentPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "report-collision-policy",
				Namespace: controllerTestNamespace,
			},
			Spec: opsv1alpha1.IncidentPolicySpec{
				Selector: metav1.LabelSelector{
					MatchLabels: map[string]string{
						"app": "collision-test",
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

		expectedFingerprint :=
			strings.Repeat(
				"b",
				64,
			)

		wrongFingerprint :=
			strings.Repeat(
				"c",
				64,
			)

		reportName :=
			incidentReportName(
				expectedFingerprint,
			)

		existingReport :=
			&opsv1alpha1.IncidentReport{
				ObjectMeta: metav1.ObjectMeta{
					Name:      reportName,
					Namespace: controllerTestNamespace,
				},

				Spec: opsv1alpha1.IncidentReportSpec{
					PolicyName: policy.Name,

					PolicyUID: string(policy.UID),

					PodName: "collision-pod",

					PodUID: "collision-pod-uid",

					ContainerName: "app",

					IncidentType: "CrashLoopBackOff",

					Fingerprint: wrongFingerprint,
				},
			}

		Expect(
			k8sClient.Create(
				ctx,
				existingReport,
			),
		).To(Succeed())

		finding :=
			&incidentFinding{
				PodName: "collision-pod",

				PodUID: "collision-pod-uid",

				ContainerName: "app",

				IncidentType: "CrashLoopBackOff",
			}

		reconciler :=
			&IncidentPolicyReconciler{
				Client: k8sClient,
			}

		err :=
			reconciler.ensureIncidentReport(
				ctx,
				policy,
				finding,
				expectedFingerprint,
			)

		Expect(err).To(HaveOccurred())

		Expect(
			err.Error(),
		).To(ContainSubstring(
			"IncidentReport name collision",
		))

		Expect(
			err.Error(),
		).To(ContainSubstring(
			expectedFingerprint,
		))

		Expect(
			err.Error(),
		).To(ContainSubstring(
			wrongFingerprint,
		))
	})

	It("returns transient Kubernetes API errors so controller-runtime can retry", func() {
		policy := &opsv1alpha1.IncidentPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "report-api-error-policy",
				Namespace: controllerTestNamespace,
			},
			Spec: opsv1alpha1.IncidentPolicySpec{
				Selector: metav1.LabelSelector{
					MatchLabels: map[string]string{
						"app": "api-error-test",
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

		fingerprint :=
			strings.Repeat(
				"d",
				64,
			)

		reportName :=
			incidentReportName(
				fingerprint,
			)

		apiFailure :=
			errors.New(
				"temporary Kubernetes API timeout",
			)

		errorClient :=
			&incidentReportGetErrorClient{
				Client:          k8sClient,
				targetNamespace: controllerTestNamespace,
				targetName:      reportName,
				injectedError:   apiFailure,
			}

		reconciler :=
			&IncidentPolicyReconciler{
				Client: errorClient,
			}

		finding :=
			&incidentFinding{
				PodName: "api-error-pod",

				PodUID: "api-error-pod-uid",

				ContainerName: "app",

				IncidentType: "CrashLoopBackOff",
			}

		err :=
			reconciler.ensureIncidentReport(
				ctx,
				policy,
				finding,
				fingerprint,
			)

		Expect(err).To(HaveOccurred())

		Expect(
			errors.Is(
				err,
				apiFailure,
			),
		).To(BeTrue())

		Expect(
			err.Error(),
		).To(ContainSubstring(
			"get IncidentReport",
		))

		Expect(
			err.Error(),
		).To(ContainSubstring(
			"temporary Kubernetes API timeout",
		))

		// Returning this error is intentional.
		// Reconcile propagates it to controller-runtime, whose workqueue
		// handles the retry with rate-limited backoff.
	})
})

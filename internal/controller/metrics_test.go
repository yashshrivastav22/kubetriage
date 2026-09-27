package controller

import (
	"context"
	"errors"

	opsv1alpha1 "github.com/yashshrivastav22/kubetriage/api/v1alpha1"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/prometheus/client_golang/prometheus/testutil"
	dto "github.com/prometheus/client_model/go"

	corev1 "k8s.io/api/core/v1"
	eventsv1 "k8s.io/api/events/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// -----------------------------------------------------------------------------
// Test clients/readers used only by the metrics suite.
// -----------------------------------------------------------------------------

type metricsPolicyGetErrorClient struct {
	client.Client
	err error
}

func (c *metricsPolicyGetErrorClient) Get(
	ctx context.Context,
	key client.ObjectKey,
	obj client.Object,
	opts ...client.GetOption,
) error {
	if _, ok := obj.(*opsv1alpha1.IncidentPolicy); ok {
		return c.err
	}

	return c.Client.Get(ctx, key, obj, opts...)
}

type metricsEventListFailureClient struct {
	client.Client
	err error
}

func (c *metricsEventListFailureClient) List(
	ctx context.Context,
	list client.ObjectList,
	opts ...client.ListOption,
) error {
	if _, ok := list.(*eventsv1.EventList); ok {
		return c.err
	}

	return c.Client.List(ctx, list, opts...)
}

type metricsFailingLogReader struct {
	err error
}

func (r *metricsFailingLogReader) ReadContainerLogs(
	ctx context.Context,
	namespace string,
	podName string,
	containerName string,
	previous bool,
	tailLines int64,
	limitBytes int64,
) ([]byte, error) {
	return nil, r.err
}

// -----------------------------------------------------------------------------
// Metric helpers.
// -----------------------------------------------------------------------------

func reconcileDurationSampleCount() uint64 {
	metric := &dto.Metric{}

	Expect(
		reconcileDuration.Write(metric),
	).To(Succeed())

	return metric.GetHistogram().GetSampleCount()
}

func createMetricsCrashLoopFixture(
	suffix string,
) (*corev1.Pod, *opsv1alpha1.IncidentPolicy) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "metrics-crash-pod-" + suffix,
			Namespace: controllerTestNamespace,
			Labels: map[string]string{
				"app": "metrics-crash-" + suffix,
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

	pod.Status.ContainerStatuses = []corev1.ContainerStatus{
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
			Name:      "metrics-crash-policy-" + suffix,
			Namespace: controllerTestNamespace,
		},
		Spec: opsv1alpha1.IncidentPolicySpec{
			Selector: metav1.LabelSelector{
				MatchLabels: map[string]string{
					"app": "metrics-crash-" + suffix,
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

	return pod, policy
}

func createMetricsEvidenceReport(
	name string,
	pod *corev1.Pod,
	podUID string,
) *opsv1alpha1.IncidentReport {
	report := &opsv1alpha1.IncidentReport{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: controllerTestNamespace,
		},
		Spec: opsv1alpha1.IncidentReportSpec{
			PolicyName:    "metrics-evidence-policy",
			PolicyUID:     "metrics-evidence-policy-uid",
			PodName:       pod.Name,
			PodUID:        podUID,
			ContainerName: "app",
			IncidentType:  "CrashLoopBackOff",
			Fingerprint:   name + "-fingerprint",
		},
	}

	Expect(
		k8sClient.Create(
			ctx,
			report,
		),
	).To(Succeed())

	stored := &opsv1alpha1.IncidentReport{}

	Expect(
		k8sClient.Get(
			ctx,
			client.ObjectKey{
				Name:      report.Name,
				Namespace: report.Namespace,
			},
			stored,
		),
	).To(Succeed())

	return stored
}

// -----------------------------------------------------------------------------
// Metrics tests.
// -----------------------------------------------------------------------------

var _ = Describe("KubeTriage metrics", func() {
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

	It("records successful reconciliations and reconcile duration", func() {
		beforeSuccess := testutil.ToFloat64(
			reconcileTotal.WithLabelValues("success"),
		)

		beforeDurationCount :=
			reconcileDurationSampleCount()

		reconciler := &IncidentPolicyReconciler{
			Client: k8sClient,
		}

		result, err := reconciler.Reconcile(
			ctx,
			ctrl.Request{
				NamespacedName: types.NamespacedName{
					Name:      "metrics-missing-policy",
					Namespace: controllerTestNamespace,
				},
			},
		)

		Expect(err).NotTo(HaveOccurred())
		Expect(result).To(Equal(ctrl.Result{}))

		afterSuccess := testutil.ToFloat64(
			reconcileTotal.WithLabelValues("success"),
		)

		afterDurationCount :=
			reconcileDurationSampleCount()

		Expect(
			afterSuccess - beforeSuccess,
		).To(Equal(float64(1)))

		Expect(
			afterDurationCount - beforeDurationCount,
		).To(Equal(uint64(1)))
	})

	It("records failed reconciliations and reconcile duration", func() {
		beforeError := testutil.ToFloat64(
			reconcileTotal.WithLabelValues("error"),
		)

		beforeDurationCount :=
			reconcileDurationSampleCount()

		injectedErr :=
			errors.New(
				"simulated IncidentPolicy API failure",
			)

		reconciler := &IncidentPolicyReconciler{
			Client: &metricsPolicyGetErrorClient{
				Client: k8sClient,
				err:    injectedErr,
			},
		}

		_, err := reconciler.Reconcile(
			ctx,
			ctrl.Request{
				NamespacedName: types.NamespacedName{
					Name:      "metrics-error-policy",
					Namespace: controllerTestNamespace,
				},
			},
		)

		Expect(err).To(HaveOccurred())

		Expect(
			errors.Is(
				err,
				injectedErr,
			),
		).To(BeTrue())

		afterError := testutil.ToFloat64(
			reconcileTotal.WithLabelValues("error"),
		)

		afterDurationCount :=
			reconcileDurationSampleCount()

		Expect(
			afterError - beforeError,
		).To(Equal(float64(1)))

		Expect(
			afterDurationCount - beforeDurationCount,
		).To(Equal(uint64(1)))
	})

	It("records incident observations by incident type", func() {
		_, policy :=
			createMetricsCrashLoopFixture(
				"observation",
			)

		before := testutil.ToFloat64(
			incidentsDetectedTotal.WithLabelValues(
				"CrashLoopBackOff",
			),
		)

		reconciler := &IncidentPolicyReconciler{
			Client: k8sClient,
		}

		_, err := reconciler.Reconcile(
			ctx,
			ctrl.Request{
				NamespacedName: types.NamespacedName{
					Name:      policy.Name,
					Namespace: policy.Namespace,
				},
			},
		)

		Expect(err).NotTo(HaveOccurred())

		after := testutil.ToFloat64(
			incidentsDetectedTotal.WithLabelValues(
				"CrashLoopBackOff",
			),
		)

		Expect(
			after - before,
		).To(Equal(float64(1)))
	})

	It("increments created only when a new IncidentReport is created", func() {
		_, policy :=
			createMetricsCrashLoopFixture(
				"created",
			)

		beforeCreated := testutil.ToFloat64(
			incidentReportTransitionsTotal.WithLabelValues(
				"created",
			),
		)

		reconciler := &IncidentPolicyReconciler{
			Client: k8sClient,
		}

		request := ctrl.Request{
			NamespacedName: types.NamespacedName{
				Name:      policy.Name,
				Namespace: policy.Namespace,
			},
		}

		_, err :=
			reconciler.Reconcile(
				ctx,
				request,
			)

		Expect(err).NotTo(HaveOccurred())

		afterFirst := testutil.ToFloat64(
			incidentReportTransitionsTotal.WithLabelValues(
				"created",
			),
		)

		Expect(
			afterFirst - beforeCreated,
		).To(Equal(float64(1)))

		// Same incident, same deterministic IncidentReport.
		_, err =
			reconciler.Reconcile(
				ctx,
				request,
			)

		Expect(err).NotTo(HaveOccurred())

		afterSecond := testutil.ToFloat64(
			incidentReportTransitionsTotal.WithLabelValues(
				"created",
			),
		)

		Expect(
			afterSecond,
		).To(Equal(afterFirst))
	})

	It("increments resolved once when an Active IncidentReport becomes Resolved", func() {
		pod, policy :=
			createMetricsCrashLoopFixture(
				"resolved",
			)

		reconciler := &IncidentPolicyReconciler{
			Client: k8sClient,
		}

		request := ctrl.Request{
			NamespacedName: types.NamespacedName{
				Name:      policy.Name,
				Namespace: policy.Namespace,
			},
		}

		// First reconciliation creates the Active report.
		_, err :=
			reconciler.Reconcile(
				ctx,
				request,
			)

		Expect(err).NotTo(HaveOccurred())

		beforeResolved := testutil.ToFloat64(
			incidentReportTransitionsTotal.WithLabelValues(
				"resolved",
			),
		)

		// Simulate container recovery.
		currentPod := &corev1.Pod{}

		Expect(
			k8sClient.Get(
				ctx,
				client.ObjectKey{
					Name:      pod.Name,
					Namespace: pod.Namespace,
				},
				currentPod,
			),
		).To(Succeed())

		currentPod.Status.ContainerStatuses =
			[]corev1.ContainerStatus{
				{
					Name:         "app",
					Image:        "busybox:1.36",
					RestartCount: 3,
					State: corev1.ContainerState{
						Running: &corev1.ContainerStateRunning{},
					},
				},
			}

		Expect(
			k8sClient.Status().Update(
				ctx,
				currentPod,
			),
		).To(Succeed())

		_, err =
			reconciler.Reconcile(
				ctx,
				request,
			)

		Expect(err).NotTo(HaveOccurred())

		afterFirstResolution :=
			testutil.ToFloat64(
				incidentReportTransitionsTotal.WithLabelValues(
					"resolved",
				),
			)

		Expect(
			afterFirstResolution - beforeResolved,
		).To(Equal(float64(1)))

		// The report is already Resolved, so another healthy reconcile
		// must not record another lifecycle transition.
		_, err =
			reconciler.Reconcile(
				ctx,
				request,
			)

		Expect(err).NotTo(HaveOccurred())

		afterSecondResolution :=
			testutil.ToFloat64(
				incidentReportTransitionsTotal.WithLabelValues(
					"resolved",
				),
			)

		Expect(
			afterSecondResolution,
		).To(Equal(afterFirstResolution))
	})

	It("records Pod evidence collection failures", func() {
		pod := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name: "metrics-pod-evidence-failure-pod",

				Namespace: controllerTestNamespace,
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

		report := createMetricsEvidenceReport(
			"metrics-pod-evidence-failure-report",
			pod,
			"old-pod-uid",
		)

		finding := &incidentFinding{
			PodName: pod.Name,

			PodUID: "old-pod-uid",

			ContainerName: "app",

			IncidentType: "CrashLoopBackOff",

			RestartCount: 4,

			CurrentState: "Waiting",

			WaitingReason: "CrashLoopBackOff",
		}

		before := testutil.ToFloat64(
			evidenceCollectionFailuresTotal.WithLabelValues(
				"pod",
			),
		)

		reconciler := &IncidentPolicyReconciler{
			Client: k8sClient,
		}

		err := reconciler.updateIncidentReportStatus(
			ctx,
			report,
			finding,
		)

		Expect(err).NotTo(HaveOccurred())

		after := testutil.ToFloat64(
			evidenceCollectionFailuresTotal.WithLabelValues(
				"pod",
			),
		)

		Expect(
			after - before,
		).To(Equal(float64(1)))
	})

	It("records Kubernetes Event evidence collection failures", func() {
		pod := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name: "metrics-event-evidence-failure-pod",

				Namespace: controllerTestNamespace,
			},
			Spec: corev1.PodSpec{
				NodeName: "metrics-node",

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

		report := createMetricsEvidenceReport(
			"metrics-event-evidence-failure-report",
			pod,
			string(pod.UID),
		)

		finding := &incidentFinding{
			PodName: pod.Name,

			PodUID: string(pod.UID),

			ContainerName: "app",

			IncidentType: "CrashLoopBackOff",

			CurrentState: "Waiting",

			WaitingReason: "CrashLoopBackOff",
		}

		before := testutil.ToFloat64(
			evidenceCollectionFailuresTotal.WithLabelValues(
				"event",
			),
		)

		reconciler := &IncidentPolicyReconciler{
			Client: &metricsEventListFailureClient{
				Client: k8sClient,
				err: errors.New(
					"simulated Event API failure",
				),
			},
		}

		err := reconciler.updateIncidentReportStatus(
			ctx,
			report,
			finding,
		)

		Expect(err).NotTo(HaveOccurred())

		after := testutil.ToFloat64(
			evidenceCollectionFailuresTotal.WithLabelValues(
				"event",
			),
		)

		Expect(
			after - before,
		).To(Equal(float64(1)))
	})

	It("records container log evidence collection failures", func() {
		pod := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name: "metrics-log-evidence-failure-pod",

				Namespace: controllerTestNamespace,
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

		report := createMetricsEvidenceReport(
			"metrics-log-evidence-failure-report",
			pod,
			string(pod.UID),
		)

		finding := &incidentFinding{
			PodName: pod.Name,

			PodUID: string(pod.UID),

			ContainerName: "app",

			IncidentType: "CrashLoopBackOff",

			RestartCount: 2,

			CurrentState: "Waiting",

			WaitingReason: "CrashLoopBackOff",

			LastTerminationReason: "Error",
		}

		before := testutil.ToFloat64(
			evidenceCollectionFailuresTotal.WithLabelValues(
				"log",
			),
		)

		reconciler := &IncidentPolicyReconciler{
			Client: k8sClient,

			LogReader: &metricsFailingLogReader{
				err: errors.New(
					"simulated Pod log failure",
				),
			},
		}

		err := reconciler.updateIncidentReportStatus(
			ctx,
			report,
			finding,
		)

		Expect(err).NotTo(HaveOccurred())

		after := testutil.ToFloat64(
			evidenceCollectionFailuresTotal.WithLabelValues(
				"log",
			),
		)

		Expect(
			after - before,
		).To(Equal(float64(1)))
	})
})

package controller

import (
	"context"
	"errors"

	opsv1alpha1 "github.com/yashshrivastav22/kubetriage/api/v1alpha1"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	corev1 "k8s.io/api/core/v1"
	eventsv1 "k8s.io/api/events/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"

	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// -----------------------------------------------------------------------------
// Status writer that can inject one conflict for a specific object.
// -----------------------------------------------------------------------------

type resourceConflictStatusWriter struct {
	client.SubResourceWriter

	targetNamespace string
	targetName      string
	resource        string
	injected        bool
}

func (w *resourceConflictStatusWriter) Patch(
	ctx context.Context,
	obj client.Object,
	patch client.Patch,
	opts ...client.SubResourcePatchOption,
) error {
	if obj.GetNamespace() == w.targetNamespace &&
		obj.GetName() == w.targetName &&
		!w.injected {

		w.injected = true

		return apierrors.NewConflict(
			schema.GroupResource{
				Group:    "ops.kubetriage.dev",
				Resource: w.resource,
			},
			obj.GetName(),
			errors.New("simulated status resource version conflict"),
		)
	}

	return w.SubResourceWriter.Patch(
		ctx,
		obj,
		patch,
		opts...,
	)
}

type resourceConflictClient struct {
	client.Client
	writer *resourceConflictStatusWriter
}

func (c *resourceConflictClient) Status() client.SubResourceWriter {
	return c.writer
}

// -----------------------------------------------------------------------------
// Client that fails only Kubernetes Event listing.
// -----------------------------------------------------------------------------

type eventListFailureClient struct {
	client.Client
	err error
}

func (c *eventListFailureClient) List(
	ctx context.Context,
	list client.ObjectList,
	opts ...client.ListOption,
) error {
	if _, ok := list.(*eventsv1.EventList); ok {
		return c.err
	}

	return c.Client.List(
		ctx,
		list,
		opts...,
	)
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

var _ = Describe("Reconcile failure classification", func() {
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

	It("propagates IncidentPolicy status conflicts for retry", func() {
		pod := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "policy-status-conflict-pod",
				Namespace: controllerTestNamespace,
				Labels: map[string]string{
					"app": "policy-status-conflict-test",
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

		policy := &opsv1alpha1.IncidentPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "policy-status-conflict-policy",
				Namespace: controllerTestNamespace,
			},
			Spec: opsv1alpha1.IncidentPolicySpec{
				Selector: metav1.LabelSelector{
					MatchLabels: map[string]string{
						"app": "policy-status-conflict-test",
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

		writer := &resourceConflictStatusWriter{
			SubResourceWriter: k8sClient.Status(),
			targetNamespace:   policy.Namespace,
			targetName:        policy.Name,
			resource:          "incidentpolicies",
		}

		wrappedClient := &resourceConflictClient{
			Client: k8sClient,
			writer: writer,
		}

		reconciler := &IncidentPolicyReconciler{
			Client: wrappedClient,
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

		Expect(err).To(HaveOccurred())
		Expect(apierrors.IsConflict(err)).To(BeTrue())
		Expect(writer.injected).To(BeTrue())
	})

	It("propagates IncidentReport resolution conflicts for retry", func() {
		pod := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "resolution-conflict-pod",
				Namespace: controllerTestNamespace,
				Labels: map[string]string{
					"app": "resolution-conflict-test",
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

		policy := &opsv1alpha1.IncidentPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "resolution-conflict-policy",
				Namespace: controllerTestNamespace,
			},
			Spec: opsv1alpha1.IncidentPolicySpec{
				Selector: metav1.LabelSelector{
					MatchLabels: map[string]string{
						"app": "resolution-conflict-test",
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

		report := &opsv1alpha1.IncidentReport{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "resolution-conflict-report",
				Namespace: controllerTestNamespace,
				Labels: map[string]string{
					reportPolicyUIDLabel:    string(policy.UID),
					reportIncidentTypeLabel: "CrashLoopBackOff",
				},
			},
			Spec: opsv1alpha1.IncidentReportSpec{
				PolicyName:    policy.Name,
				PolicyUID:     string(policy.UID),
				PodName:       "old-failing-pod",
				PodUID:        "old-failing-pod-uid",
				ContainerName: "app",
				IncidentType:  "CrashLoopBackOff",
				Fingerprint:   "resolution-conflict-fingerprint",
			},
		}

		Expect(
			k8sClient.Create(
				ctx,
				report,
			),
		).To(Succeed())

		now := metav1.Now()

		report.Status.Phase = "Active"
		report.Status.FirstDetectedAt = &now
		report.Status.LastObservedAt = &now

		Expect(
			k8sClient.Status().Update(
				ctx,
				report,
			),
		).To(Succeed())

		writer := &resourceConflictStatusWriter{
			SubResourceWriter: k8sClient.Status(),
			targetNamespace:   report.Namespace,
			targetName:        report.Name,
			resource:          "incidentreports",
		}

		wrappedClient := &resourceConflictClient{
			Client: k8sClient,
			writer: writer,
		}

		reconciler := &IncidentPolicyReconciler{
			Client: wrappedClient,
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

		Expect(err).To(HaveOccurred())
		Expect(apierrors.IsConflict(err)).To(BeTrue())
		Expect(writer.injected).To(BeTrue())

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

		// Failed status patch means the report remains Active.
		Expect(stored.Status.Phase).To(Equal("Active"))
	})

	It("keeps an incident active when Kubernetes Event collection fails", func() {
		pod := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "event-failure-pod",
				Namespace: controllerTestNamespace,
			},
			Spec: corev1.PodSpec{
				NodeName: "worker-event-failure",
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
			},
		}

		Expect(
			k8sClient.Status().Update(
				ctx,
				pod,
			),
		).To(Succeed())

		report := &opsv1alpha1.IncidentReport{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "event-failure-report",
				Namespace: controllerTestNamespace,
			},
			Spec: opsv1alpha1.IncidentReportSpec{
				PolicyName:    "event-failure-policy",
				PolicyUID:     "event-failure-policy-uid",
				PodName:       pod.Name,
				PodUID:        string(pod.UID),
				ContainerName: "app",
				IncidentType:  "CrashLoopBackOff",
				Fingerprint:   "event-failure-fingerprint",
			},
		}

		Expect(
			k8sClient.Create(
				ctx,
				report,
			),
		).To(Succeed())

		now := metav1.Now()

		report.Status.Phase = "Active"
		report.Status.FirstDetectedAt = &now
		report.Status.LastObservedAt = &now
		report.Status.Evidence.Events =
			[]opsv1alpha1.IncidentEventEvidence{
				{
					Type:   "Warning",
					Reason: "ExistingEvidence",
					Note:   "previously collected event evidence",
				},
			}

		Expect(
			k8sClient.Status().Update(
				ctx,
				report,
			),
		).To(Succeed())

		storedReport := &opsv1alpha1.IncidentReport{}

		Expect(
			k8sClient.Get(
				ctx,
				client.ObjectKey{
					Name:      report.Name,
					Namespace: report.Namespace,
				},
				storedReport,
			),
		).To(Succeed())

		eventFailure := errors.New(
			"simulated events API failure",
		)

		wrappedClient := &eventListFailureClient{
			Client: k8sClient,
			err:    eventFailure,
		}

		reconciler := &IncidentPolicyReconciler{
			Client: wrappedClient,
		}

		finding := &incidentFinding{
			PodName:       pod.Name,
			PodUID:        string(pod.UID),
			ContainerName: "app",
			IncidentType:  "CrashLoopBackOff",
			RestartCount:  3,
			CurrentState:  "Waiting",
			WaitingReason: "CrashLoopBackOff",
		}

		err := reconciler.updateIncidentReportStatus(
			ctx,
			storedReport,
			finding,
		)

		// Event evidence failure is supplemental and therefore must not
		// fail the incident status update.
		Expect(err).NotTo(HaveOccurred())

		updated := &opsv1alpha1.IncidentReport{}

		Expect(
			k8sClient.Get(
				ctx,
				client.ObjectKey{
					Name:      report.Name,
					Namespace: report.Namespace,
				},
				updated,
			),
		).To(Succeed())

		Expect(updated.Status.Phase).To(Equal("Active"))

		// Older useful evidence is preserved when refresh fails.
		Expect(updated.Status.Evidence.Events).To(HaveLen(1))

		Expect(
			updated.Status.Evidence.Events[0].Reason,
		).To(Equal("ExistingEvidence"))

		// Pod/container evidence still refreshed successfully.
		Expect(
			updated.Status.Evidence.NodeName,
		).To(Equal("worker-event-failure"))

		Expect(
			updated.Status.Evidence.RestartCount,
		).To(Equal(int32(3)))

		Expect(
			updated.Status.Evidence.WaitingReason,
		).To(Equal("CrashLoopBackOff"))
	})

	It("keeps detector evidence when rich Pod evidence collection fails", func() {
		pod := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "pod-evidence-failure-pod",
				Namespace: controllerTestNamespace,
			},
			Spec: corev1.PodSpec{
				NodeName: "replacement-node",
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

		report := &opsv1alpha1.IncidentReport{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "pod-evidence-failure-report",
				Namespace: controllerTestNamespace,
			},
			Spec: opsv1alpha1.IncidentReportSpec{
				PolicyName:    "pod-evidence-failure-policy",
				PolicyUID:     "pod-evidence-failure-policy-uid",
				PodName:       pod.Name,
				PodUID:        "original-pod-uid",
				ContainerName: "app",
				IncidentType:  "CrashLoopBackOff",
				Fingerprint:   "pod-evidence-failure-fingerprint",
			},
		}

		Expect(
			k8sClient.Create(
				ctx,
				report,
			),
		).To(Succeed())

		storedReport := &opsv1alpha1.IncidentReport{}

		Expect(
			k8sClient.Get(
				ctx,
				client.ObjectKey{
					Name:      report.Name,
					Namespace: report.Namespace,
				},
				storedReport,
			),
		).To(Succeed())

		reconciler := &IncidentPolicyReconciler{
			Client: k8sClient,
		}

		finding := &incidentFinding{
			PodName: pod.Name,

			// Deliberately different from the current Pod UID.
			PodUID: "original-pod-uid",

			ContainerName: "app",
			IncidentType:  "CrashLoopBackOff",

			RestartCount:  7,
			CurrentState:  "Waiting",
			WaitingReason: "CrashLoopBackOff",
		}

		err := reconciler.updateIncidentReportStatus(
			ctx,
			storedReport,
			finding,
		)

		// Rich evidence failure does not invalidate the detected incident.
		Expect(err).NotTo(HaveOccurred())

		updated := &opsv1alpha1.IncidentReport{}

		Expect(
			k8sClient.Get(
				ctx,
				client.ObjectKey{
					Name:      report.Name,
					Namespace: report.Namespace,
				},
				updated,
			),
		).To(Succeed())

		Expect(updated.Status.Phase).To(Equal("Active"))

		// Detector-derived fallback evidence survives.
		Expect(
			updated.Status.Evidence.RestartCount,
		).To(Equal(int32(7)))

		Expect(
			updated.Status.Evidence.CurrentState,
		).To(Equal("Waiting"))

		Expect(
			updated.Status.Evidence.WaitingReason,
		).To(Equal("CrashLoopBackOff"))

		// Data from the replacement Pod must not leak into the report.
		Expect(
			updated.Status.Evidence.NodeName,
		).To(BeEmpty())

		Expect(
			updated.Status.Evidence.ConfiguredImage,
		).To(BeEmpty())
	})
})

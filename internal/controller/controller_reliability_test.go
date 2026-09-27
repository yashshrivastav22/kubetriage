package controller

import (
	"context"
	"errors"

	opsv1alpha1 "github.com/yashshrivastav22/kubetriage/api/v1alpha1"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"

	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// -----------------------------------------------------------------------------
// Status writer that injects one Kubernetes conflict.
// -----------------------------------------------------------------------------

type conflictStatusWriter struct {
	client.SubResourceWriter

	targetNamespace string
	targetName      string
	injected        bool
}

func (w *conflictStatusWriter) Patch(
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
				Resource: "incidentreports",
			},
			obj.GetName(),
			errors.New("simulated resource version conflict"),
		)
	}

	return w.SubResourceWriter.Patch(
		ctx,
		obj,
		patch,
		opts...,
	)
}

type conflictStatusClient struct {
	client.Client

	writer *conflictStatusWriter
}

func (c *conflictStatusClient) Status() client.SubResourceWriter {
	return c.writer
}

// -----------------------------------------------------------------------------
// Reliability tests.
// -----------------------------------------------------------------------------

var _ = Describe("Controller reliability", func() {
	It("returns nil when the requested IncidentPolicy has already been deleted", func() {
		reconciler := &IncidentPolicyReconciler{
			Client: k8sClient,
		}

		result, err := reconciler.Reconcile(
			ctx,
			ctrl.Request{
				NamespacedName: types.NamespacedName{
					Name:      "policy-that-does-not-exist",
					Namespace: controllerTestNamespace,
				},
			},
		)

		Expect(err).NotTo(HaveOccurred())
		Expect(result).To(Equal(ctrl.Result{}))
	})

	It("propagates an IncidentReport status conflict so controller-runtime can retry", func() {
		report := &opsv1alpha1.IncidentReport{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "status-conflict-report",
				Namespace: controllerTestNamespace,
			},
			Spec: opsv1alpha1.IncidentReportSpec{
				PolicyName:    "status-conflict-policy",
				PolicyUID:     "status-conflict-policy-uid",
				PodName:       "status-conflict-pod",
				PodUID:        "status-conflict-pod-uid",
				ContainerName: "app",
				IncidentType:  "CrashLoopBackOff",
				Fingerprint:   "status-conflict-fingerprint",
			},
		}

		Expect(
			k8sClient.Create(
				ctx,
				report,
			),
		).To(Succeed())

		Expect(
			k8sClient.Get(
				ctx,
				client.ObjectKey{
					Name:      report.Name,
					Namespace: report.Namespace,
				},
				report,
			),
		).To(Succeed())

		writer := &conflictStatusWriter{
			SubResourceWriter: k8sClient.Status(),
			targetNamespace:   report.Namespace,
			targetName:        report.Name,
		}

		wrappedClient := &conflictStatusClient{
			Client: k8sClient,
			writer: writer,
		}

		reconciler := &IncidentPolicyReconciler{
			Client: wrappedClient,
		}

		finding := &incidentFinding{
			PodName:       "status-conflict-pod",
			PodUID:        "status-conflict-pod-uid",
			ContainerName: "app",
			IncidentType:  "CrashLoopBackOff",
			RestartCount:  5,
			CurrentState:  "Waiting",
			WaitingReason: "CrashLoopBackOff",
		}

		err := reconciler.updateIncidentReportStatus(
			ctx,
			report,
			finding,
		)

		Expect(err).To(HaveOccurred())
		Expect(apierrors.IsConflict(err)).To(BeTrue())
		Expect(writer.injected).To(BeTrue())
	})
})

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

const incidentReportTestNamespace = "kubetriage-incidentreport-test"

var _ = Describe("IncidentReport API validation", func() {

	BeforeEach(func() {
		namespace := &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name: incidentReportTestNamespace,
			},
		}

		err := k8sClient.Create(ctx, namespace)

		if err != nil && !apierrors.IsAlreadyExists(err) {
			Expect(err).NotTo(HaveOccurred())
		}
	})

	AfterEach(func() {
		reports := &opsv1alpha1.IncidentReportList{}

		Expect(
			k8sClient.List(
				ctx,
				reports,
				client.InNamespace(incidentReportTestNamespace),
			),
		).To(Succeed())

		for i := range reports.Items {
			Expect(
				k8sClient.Delete(
					ctx,
					&reports.Items[i],
				),
			).To(Succeed())
		}
	})

	It("accepts a valid IncidentReport", func() {
		report := validIncidentReport(
			"valid-report",
		)

		Expect(
			k8sClient.Create(
				ctx,
				report,
			),
		).To(Succeed())
	})

	It("rejects an IncidentReport with an empty fingerprint", func() {
		report := validIncidentReport(
			"missing-fingerprint",
		)

		report.Spec.Fingerprint = ""

		err := k8sClient.Create(
			ctx,
			report,
		)

		Expect(err).To(HaveOccurred())

		Expect(
			apierrors.IsInvalid(err),
		).To(BeTrue())
	})

	It("rejects an unsupported incident type", func() {
		report := validIncidentReport(
			"invalid-incident-type",
		)

		report.Spec.IncidentType = "NodeExplosion"

		err := k8sClient.Create(
			ctx,
			report,
		)

		Expect(err).To(HaveOccurred())

		Expect(
			apierrors.IsInvalid(err),
		).To(BeTrue())
	})

	It("accepts Active as a valid lifecycle phase", func() {
		report := validIncidentReport(
			"active-report",
		)

		Expect(
			k8sClient.Create(
				ctx,
				report,
			),
		).To(Succeed())

		report.Status.Phase = "Active"

		Expect(
			k8sClient.Status().Update(
				ctx,
				report,
			),
		).To(Succeed())
	})

	It("accepts Resolved as a valid lifecycle phase", func() {
		report := validIncidentReport(
			"resolved-report",
		)

		Expect(
			k8sClient.Create(
				ctx,
				report,
			),
		).To(Succeed())

		report.Status.Phase = "Resolved"

		Expect(
			k8sClient.Status().Update(
				ctx,
				report,
			),
		).To(Succeed())
	})

	It("rejects an invalid lifecycle phase", func() {
		report := validIncidentReport(
			"invalid-phase-report",
		)

		Expect(
			k8sClient.Create(
				ctx,
				report,
			),
		).To(Succeed())

		report.Status.Phase = "Broken"

		err := k8sClient.Status().Update(
			ctx,
			report,
		)

		Expect(err).To(HaveOccurred())

		Expect(
			apierrors.IsInvalid(err),
		).To(BeTrue())
	})
})

func validIncidentReport(
	name string,
) *opsv1alpha1.IncidentReport {
	return &opsv1alpha1.IncidentReport{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: incidentReportTestNamespace,
		},

		Spec: opsv1alpha1.IncidentReportSpec{
			PolicyName:    "checkout-monitor",
			PolicyUID:     "policy-uid-123",
			PodName:       "checkout-abc123",
			PodUID:        "pod-uid-456",
			ContainerName: "checkout",
			IncidentType:  "CrashLoopBackOff",
			Fingerprint:   "fingerprint-123",
		},
	}
}

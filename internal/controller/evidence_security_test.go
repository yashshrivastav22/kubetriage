package controller

import (
	"context"
	"encoding/json"
	"time"

	opsv1alpha1 "github.com/yashshrivastav22/kubetriage/api/v1alpha1"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	corev1 "k8s.io/api/core/v1"
	eventsv1 "k8s.io/api/events/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

// -----------------------------------------------------------------------------
// Fake log reader used by the security integration test.
// -----------------------------------------------------------------------------

type securityEvidenceLogReader struct {
	currentData  []byte
	previousData []byte
}

func (r *securityEvidenceLogReader) ReadContainerLogs(
	ctx context.Context,
	namespace string,
	podName string,
	containerName string,
	previous bool,
	tailLines int64,
	limitBytes int64,
) ([]byte, error) {
	if previous {
		return r.previousData, nil
	}

	return r.currentData, nil
}

// -----------------------------------------------------------------------------
// Security integration tests.
// -----------------------------------------------------------------------------

var _ = Describe("Incident evidence security", func() {
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

	It("redacts supported secret patterns before evidence is stored in IncidentReport", func() {
		pod := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "security-evidence-pod",
				Namespace: controllerTestNamespace,
			},
			Spec: corev1.PodSpec{
				NodeName: "security-test-node",
				Containers: []corev1.Container{
					{
						Name:  "app",
						Image: "example/app:v1",
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

		exitCode := int32(1)

		pod.Status.ContainerStatuses = []corev1.ContainerStatus{
			{
				Name:         "app",
				Image:        "example/app:v1",
				ImageID:      "containerd://sha256:security-test",
				ContainerID:  "containerd://current-security-test",
				RestartCount: 2,
				State: corev1.ContainerState{
					Waiting: &corev1.ContainerStateWaiting{
						Reason: "CrashLoopBackOff",
					},
				},
				LastTerminationState: corev1.ContainerState{
					Terminated: &corev1.ContainerStateTerminated{
						ExitCode:    1,
						Reason:      "Error",
						Message:     "startup failed password=termination-secret-value",
						ContainerID: "containerd://previous-security-test",
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

		event := &eventsv1.Event{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "security-evidence-event",
				Namespace: controllerTestNamespace,
			},
			EventTime: metav1.NewMicroTime(
				time.Now(),
			),
			Regarding: corev1.ObjectReference{
				APIVersion: "v1",
				Kind:       "Pod",
				Namespace:  pod.Namespace,
				Name:       pod.Name,
				UID:        pod.UID,
			},
			Reason:              "BackOff",
			Note:                "request failed Authorization: Bearer event-secret-token",
			Type:                "Warning",
			Action:              "BackOff",
			ReportingController: "kubetriage-security-test",
			ReportingInstance:   "kubetriage-security-test-1",
		}

		Expect(
			k8sClient.Create(
				ctx,
				event,
			),
		).To(Succeed())

		report := &opsv1alpha1.IncidentReport{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "security-evidence-report",
				Namespace: controllerTestNamespace,
			},
			Spec: opsv1alpha1.IncidentReportSpec{
				PolicyName:    "security-evidence-policy",
				PolicyUID:     "security-evidence-policy-uid",
				PodName:       pod.Name,
				PodUID:        string(pod.UID),
				ContainerName: "app",
				IncidentType:  "CrashLoopBackOff",
				Fingerprint:   "security-evidence-fingerprint",
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

		finding := &incidentFinding{
			PodName:               pod.Name,
			PodUID:                string(pod.UID),
			ContainerName:         "app",
			IncidentType:          "CrashLoopBackOff",
			RestartCount:          2,
			CurrentState:          "Waiting",
			WaitingReason:         "CrashLoopBackOff",
			LastTerminationReason: "Error",
			ExitCode:              &exitCode,
		}

		logReader := &securityEvidenceLogReader{
			currentData: []byte(
				"connecting to backend api_key=current-secret-value\n",
			),
			previousData: []byte(
				"database connection postgres://admin:previous-secret-value@db:5432/app failed\n",
			),
		}

		reconciler := &IncidentPolicyReconciler{
			Client:    k8sClient,
			LogReader: logReader,
		}

		Expect(
			reconciler.updateIncidentReportStatus(
				ctx,
				storedReport,
				finding,
			),
		).To(Succeed())

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

		Expect(updated.Status.Phase).To(
			Equal("Active"),
		)

		// -----------------------------------------------------------------
		// Termination message
		// -----------------------------------------------------------------

		Expect(
			updated.Status.Evidence.TerminationMessage,
		).To(ContainSubstring(
			"password=[REDACTED]",
		))

		Expect(
			updated.Status.Evidence.TerminationMessage,
		).NotTo(ContainSubstring(
			"termination-secret-value",
		))

		// -----------------------------------------------------------------
		// Kubernetes Event
		// -----------------------------------------------------------------

		Expect(
			updated.Status.Evidence.Events,
		).To(HaveLen(1))

		Expect(
			updated.Status.Evidence.Events[0].Note,
		).To(ContainSubstring(
			"Authorization: Bearer [REDACTED]",
		))

		Expect(
			updated.Status.Evidence.Events[0].Note,
		).NotTo(ContainSubstring(
			"event-secret-token",
		))

		// -----------------------------------------------------------------
		// Current logs
		// -----------------------------------------------------------------

		Expect(
			updated.Status.Evidence.Logs.Current,
		).To(ContainSubstring(
			"api_key=[REDACTED]",
		))

		Expect(
			updated.Status.Evidence.Logs.Current,
		).NotTo(ContainSubstring(
			"current-secret-value",
		))

		// -----------------------------------------------------------------
		// Previous logs
		// -----------------------------------------------------------------

		Expect(
			updated.Status.Evidence.Logs.Previous,
		).To(ContainSubstring(
			"postgres://[REDACTED]@db:5432/app",
		))

		Expect(
			updated.Status.Evidence.Logs.Previous,
		).NotTo(ContainSubstring(
			"previous-secret-value",
		))

		// -----------------------------------------------------------------
		// Final persistence boundary.
		//
		// Serialize the actual stored evidence and make sure none of our
		// raw test secrets survived anywhere in the object.
		// -----------------------------------------------------------------

		storedEvidenceJSON, err :=
			json.Marshal(
				updated.Status.Evidence,
			)

		Expect(err).NotTo(HaveOccurred())

		storedEvidence :=
			string(storedEvidenceJSON)

		rawSecrets := []string{
			"termination-secret-value",
			"event-secret-token",
			"current-secret-value",
			"previous-secret-value",
		}

		for _, secret := range rawSecrets {
			Expect(
				storedEvidence,
			).NotTo(ContainSubstring(secret))
		}

		Expect(
			storedEvidence,
		).To(ContainSubstring(
			redactedEvidenceValue,
		))
	})
})

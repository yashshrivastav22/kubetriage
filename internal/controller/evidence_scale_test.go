package controller

import (
	"context"
	"fmt"
	"strings"
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

type scaleEvidenceLogReader struct {
	current  []byte
	previous []byte
}

func (r *scaleEvidenceLogReader) ReadContainerLogs(
	ctx context.Context,
	namespace string,
	podName string,
	containerName string,
	previous bool,
	tailLines int64,
	limitBytes int64,
) ([]byte, error) {
	if previous {
		return r.previous, nil
	}

	return r.current, nil
}

var _ = Describe("Evidence scale validation", func() {
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

	It("keeps large Event and log evidence bounded in IncidentReport status", func() {
		pod := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "bounded-evidence-pod",
				Namespace: controllerTestNamespace,
			},
			Spec: corev1.PodSpec{
				NodeName: "scale-test-node",
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

		pod.Status.ContainerStatuses =
			[]corev1.ContainerStatus{
				{
					Name:         "app",
					Image:        "busybox:1.36",
					ImageID:      "containerd://sha256:bounded-evidence",
					ContainerID:  "containerd://bounded-current",
					RestartCount: 4,
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
							Message: strings.Repeat(
								"termination-message-",
								200,
							),
							ContainerID: "containerd://bounded-previous",
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

		// -------------------------------------------------------------
		// Create more Kubernetes Events than KubeTriage is allowed
		// to store.
		// -------------------------------------------------------------

		const totalEvents = 25

		for i := 0; i < totalEvents; i++ {
			event := &eventsv1.Event{
				ObjectMeta: metav1.ObjectMeta{
					Name: fmt.Sprintf(
						"bounded-evidence-event-%02d",
						i,
					),
					Namespace: controllerTestNamespace,
				},

				EventTime: metav1.NewMicroTime(
					time.Now().Add(
						time.Duration(i) * time.Second,
					),
				),

				Regarding: corev1.ObjectReference{
					APIVersion: "v1",

					Kind: "Pod",

					Namespace: pod.Namespace,

					Name: pod.Name,

					UID: pod.UID,
				},

				Reason: "BackOff",

				Note: strings.Repeat(
					fmt.Sprintf(
						"event-%02d ",
						i,
					),
					100,
				),

				Type: "Warning",

				Action: "BackOff",

				ReportingController: "kubetriage-scale-test",

				ReportingInstance: fmt.Sprintf(
					"kubetriage-scale-test-%02d",
					i,
				),
			}

			Expect(
				k8sClient.Create(
					ctx,
					event,
				),
			).To(Succeed())
		}

		// -------------------------------------------------------------
		// Supply logs far larger than the IncidentReport storage limit.
		//
		// The fake intentionally ignores limitBytes so this also proves
		// KubeTriage enforces its own local persistence boundary.
		// -------------------------------------------------------------

		logReader :=
			&scaleEvidenceLogReader{
				current: []byte(
					strings.Repeat(
						"current-log-data ",
						2000,
					),
				),

				previous: []byte(
					strings.Repeat(
						"previous-log-data ",
						2000,
					),
				),
			}

		report :=
			&opsv1alpha1.IncidentReport{
				ObjectMeta: metav1.ObjectMeta{
					Name: "bounded-evidence-report",

					Namespace: controllerTestNamespace,
				},

				Spec: opsv1alpha1.IncidentReportSpec{
					PolicyName: "bounded-evidence-policy",

					PolicyUID: "bounded-evidence-policy-uid",

					PodName: pod.Name,

					PodUID: string(pod.UID),

					ContainerName: "app",

					IncidentType: "CrashLoopBackOff",

					Fingerprint: "bounded-evidence-fingerprint",
				},
			}

		Expect(
			k8sClient.Create(
				ctx,
				report,
			),
		).To(Succeed())

		storedReport :=
			&opsv1alpha1.IncidentReport{}

		Expect(
			k8sClient.Get(
				ctx,
				client.ObjectKey{
					Name: report.Name,

					Namespace: report.Namespace,
				},
				storedReport,
			),
		).To(Succeed())

		exitCode :=
			int32(1)

		finding :=
			&incidentFinding{
				PodName: pod.Name,

				PodUID: string(pod.UID),

				ContainerName: "app",

				IncidentType: "CrashLoopBackOff",

				Message: "container is repeatedly failing",

				RestartCount: 4,

				CurrentState: "Waiting",

				WaitingReason: "CrashLoopBackOff",

				LastTerminationReason: "Error",

				ExitCode: &exitCode,
			}

		reconciler :=
			&IncidentPolicyReconciler{
				Client: k8sClient,

				LogReader: logReader,
			}

		Expect(
			reconciler.updateIncidentReportStatus(
				ctx,
				storedReport,
				finding,
			),
		).To(Succeed())

		updated :=
			&opsv1alpha1.IncidentReport{}

		Expect(
			k8sClient.Get(
				ctx,
				client.ObjectKey{
					Name: report.Name,

					Namespace: report.Namespace,
				},
				updated,
			),
		).To(Succeed())

		// -------------------------------------------------------------
		// Event bounding
		// -------------------------------------------------------------

		Expect(
			updated.Status.Evidence.Events,
		).To(HaveLen(
			maxIncidentEvents,
		))

		for i := range updated.Status.Evidence.Events {
			eventEvidence :=
				&updated.Status.Evidence.Events[i]

			Expect(
				len(
					[]rune(
						eventEvidence.Note,
					),
				),
			).To(BeNumerically(
				"<=",
				maxIncidentEventNoteRunes,
			))
		}

		// -------------------------------------------------------------
		// Termination-message bounding
		// -------------------------------------------------------------

		Expect(
			len(
				[]rune(
					updated.Status.Evidence.TerminationMessage,
				),
			),
		).To(BeNumerically(
			"<=",
			maxTerminationMessageRunes,
		))

		// -------------------------------------------------------------
		// Log bounding
		// -------------------------------------------------------------

		Expect(
			len(
				[]byte(
					updated.Status.Evidence.Logs.Current,
				),
			),
		).To(BeNumerically(
			"<=",
			incidentLogLimitBytes,
		))

		Expect(
			len(
				[]byte(
					updated.Status.Evidence.Logs.Previous,
				),
			),
		).To(BeNumerically(
			"<=",
			incidentLogLimitBytes,
		))

		Expect(
			updated.Status.Evidence.Logs.CurrentTruncated,
		).To(BeTrue())

		Expect(
			updated.Status.Evidence.Logs.PreviousTruncated,
		).To(BeTrue())

		// -------------------------------------------------------------
		// Basic lifecycle integrity.
		// -------------------------------------------------------------

		Expect(
			string(
				updated.Status.Phase,
			),
		).To(Equal(
			"Active",
		))

		Expect(
			updated.Status.FirstDetectedAt,
		).NotTo(BeNil())

		Expect(
			updated.Status.LastObservedAt,
		).NotTo(BeNil())

		GinkgoWriter.Printf(
			"bounded evidence validation: source events=%d stored events=%d current log bytes=%d previous log bytes=%d termination runes=%d\n",
			totalEvents,
			len(updated.Status.Evidence.Events),
			len([]byte(updated.Status.Evidence.Logs.Current)),
			len([]byte(updated.Status.Evidence.Logs.Previous)),
			len([]rune(updated.Status.Evidence.TerminationMessage)),
		)
	})
})

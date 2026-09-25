package controller

import (
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

var _ = Describe("Kubernetes Event evidence", func() {

	BeforeEach(func() {
		namespace := &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name: controllerTestNamespace,
			},
		}

		err := k8sClient.Create(ctx, namespace)

		if err != nil && !apierrors.IsAlreadyExists(err) {
			Expect(err).NotTo(HaveOccurred())
		}
	})

	// ---------------------------------------------------------------------
	// TEST 1
	// Collect only Events belonging to the affected Pod.
	// ---------------------------------------------------------------------

	It("collects Events for the affected Pod and ignores unrelated Pod Events", func() {
		targetPod := createEventEvidencePod(
			"event-target-pod",
			map[string]string{
				"app": "event-target",
			},
		)

		unrelatedPod := createEventEvidencePod(
			"event-unrelated-pod",
			map[string]string{
				"app": "event-unrelated",
			},
		)

		baseTime := time.Date(
			2026,
			time.September,
			24,
			20,
			0,
			0,
			0,
			time.UTC,
		)

		// Older Event.
		createEventEvidenceEvent(
			"target-pulled-event",
			targetPod,
			"Normal",
			"Pulled",
			"PulledImage",
			"Successfully pulled container image",
			baseTime,
			nil,
		)

		// Newer Event series.
		seriesTime := baseTime.Add(2 * time.Minute)

		createEventEvidenceEvent(
			"target-backoff-event",
			targetPod,
			"Warning",
			"BackOff",
			"BackOff",
			"Back-off restarting failed container app",
			baseTime.Add(time.Minute),
			&eventsv1.EventSeries{
				Count: 8,
				LastObservedTime: metav1.NewMicroTime(
					seriesTime,
				),
			},
		)

		// Event belonging to another Pod.
		createEventEvidenceEvent(
			"unrelated-event",
			unrelatedPod,
			"Warning",
			"Failed",
			"SomethingFailed",
			"This event belongs to another Pod",
			baseTime.Add(5*time.Minute),
			nil,
		)

		reconciler := &IncidentPolicyReconciler{
			Client: k8sClient,
		}

		evidence, err := reconciler.collectPodEventEvidence(
			ctx,
			controllerTestNamespace,
			string(targetPod.UID),
		)

		Expect(err).NotTo(HaveOccurred())

		// Only targetPod Events should be returned.
		Expect(evidence).To(HaveLen(2))

		// Newest Event first.
		Expect(evidence[0].Reason).To(Equal("BackOff"))
		Expect(evidence[0].Type).To(Equal("Warning"))
		Expect(evidence[0].Action).To(Equal("BackOff"))
		Expect(evidence[0].Count).To(Equal(int32(8)))

		Expect(evidence[0].Note).To(
			ContainSubstring("Back-off restarting failed container"),
		)

		Expect(evidence[0].ReportingController).To(
			Equal("kubetriage.test/kubelet"),
		)

		Expect(evidence[0].FirstObservedAt).NotTo(BeNil())

		Expect(
			evidence[0].FirstObservedAt.Time.Equal(
				baseTime.Add(time.Minute),
			),
		).To(BeTrue())

		Expect(evidence[0].LastObservedAt).NotTo(BeNil())

		Expect(
			evidence[0].LastObservedAt.Time.Equal(seriesTime),
		).To(BeTrue())

		// Singleton Event should have count 1.
		Expect(evidence[1].Reason).To(Equal("Pulled"))
		Expect(evidence[1].Count).To(Equal(int32(1)))

		// Unrelated Pod Event must not be included.
		for _, item := range evidence {
			Expect(item.Note).NotTo(
				ContainSubstring("another Pod"),
			)
		}
	})

	// ---------------------------------------------------------------------
	// TEST 2
	// Store only the newest 10 Events.
	// ---------------------------------------------------------------------

	It("stores only the newest ten Events", func() {
		pod := createEventEvidencePod(
			"bounded-events-pod",
			map[string]string{
				"app": "bounded-events",
			},
		)

		baseTime := time.Date(
			2026,
			time.September,
			24,
			21,
			0,
			0,
			0,
			time.UTC,
		)

		// Create 12 Events.
		//
		// Reason00 = oldest
		// Reason11 = newest
		for i := 0; i < 12; i++ {
			createEventEvidenceEvent(
				fmt.Sprintf("bounded-event-%02d", i),
				pod,
				"Warning",
				fmt.Sprintf("Reason%02d", i),
				"Testing",
				fmt.Sprintf("event number %02d", i),
				baseTime.Add(time.Duration(i)*time.Minute),
				nil,
			)
		}

		reconciler := &IncidentPolicyReconciler{
			Client: k8sClient,
		}

		evidence, err := reconciler.collectPodEventEvidence(
			ctx,
			controllerTestNamespace,
			string(pod.UID),
		)

		Expect(err).NotTo(HaveOccurred())

		Expect(evidence).To(HaveLen(maxIncidentEvents))

		// Newest first.
		Expect(evidence[0].Reason).To(Equal("Reason11"))

		// Ten newest:
		// 11,10,9,8,7,6,5,4,3,2
		Expect(evidence[9].Reason).To(Equal("Reason02"))

		for _, item := range evidence {
			Expect(item.Reason).NotTo(Equal("Reason00"))
			Expect(item.Reason).NotTo(Equal("Reason01"))
		}
	})

	// ---------------------------------------------------------------------
	// TEST 3
	// Unicode-safe Event note truncation.
	// ---------------------------------------------------------------------

	It("truncates long Event notes without breaking Unicode characters", func() {
		longNote := strings.Repeat(
			"🙂",
			maxIncidentEventNoteRunes+100,
		)

		truncated := truncateRunes(
			longNote,
			maxIncidentEventNoteRunes,
		)

		truncatedRunes := []rune(truncated)

		Expect(truncatedRunes).To(
			HaveLen(maxIncidentEventNoteRunes),
		)

		Expect(
			string(truncatedRunes[len(truncatedRunes)-1]),
		).To(Equal("🙂"))

		shortNote := "Back-off restarting failed container"

		Expect(
			truncateRunes(
				shortNote,
				maxIncidentEventNoteRunes,
			),
		).To(Equal(shortNote))
	})

	// ---------------------------------------------------------------------
	// TEST 4
	// Collected Event evidence reaches IncidentReport status.
	// ---------------------------------------------------------------------

	It("stores Pod Event evidence in the IncidentReport", func() {
		pod := createEventEvidencePod(
			"report-event-pod",
			map[string]string{
				"app": "report-event-test",
			},
		)

		// envtest has no kubelet, so simulate CrashLoopBackOff.
		pod.Status.ContainerStatuses = []corev1.ContainerStatus{
			{
				Name:         "app",
				RestartCount: 7,
				State: corev1.ContainerState{
					Waiting: &corev1.ContainerStateWaiting{
						Reason:  "CrashLoopBackOff",
						Message: "back-off restarting failed container",
					},
				},
			},
		}

		Expect(
			k8sClient.Status().Update(ctx, pod),
		).To(Succeed())

		eventTime := time.Date(
			2026,
			time.September,
			24,
			22,
			0,
			0,
			0,
			time.UTC,
		)

		createEventEvidenceEvent(
			"report-backoff-event",
			pod,
			"Warning",
			"BackOff",
			"BackOff",
			"Back-off restarting failed container app",
			eventTime,
			&eventsv1.EventSeries{
				Count: 6,
				LastObservedTime: metav1.NewMicroTime(
					eventTime.Add(30 * time.Second),
				),
			},
		)

		policy := &opsv1alpha1.IncidentPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "report-event-policy",
				Namespace: controllerTestNamespace,
			},
			Spec: opsv1alpha1.IncidentPolicySpec{
				Selector: metav1.LabelSelector{
					MatchLabels: map[string]string{
						"app": "report-event-test",
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

		reconcilePolicy(
			policy.Name,
		)

		reports := &opsv1alpha1.IncidentReportList{}

		Expect(
			k8sClient.List(
				ctx,
				reports,
				client.InNamespace(controllerTestNamespace),
				client.MatchingLabels{
					reportPolicyUIDLabel: string(policy.UID),
				},
			),
		).To(Succeed())

		Expect(reports.Items).To(HaveLen(1))

		report := &reports.Items[0]

		Expect(report.Status.Phase).To(Equal("Active"))

		Expect(
			report.Status.Evidence.RestartCount,
		).To(Equal(int32(7)))

		Expect(
			report.Status.Evidence.Events,
		).To(HaveLen(1))

		storedEvent := report.Status.Evidence.Events[0]

		Expect(storedEvent.Type).To(Equal("Warning"))
		Expect(storedEvent.Reason).To(Equal("BackOff"))
		Expect(storedEvent.Action).To(Equal("BackOff"))
		Expect(storedEvent.Count).To(Equal(int32(6)))

		Expect(storedEvent.Note).To(
			ContainSubstring(
				"Back-off restarting failed container",
			),
		)

		Expect(storedEvent.ReportingController).To(
			Equal("kubetriage.test/kubelet"),
		)
	})
})

// -----------------------------------------------------------------------------
// Test helpers
// -----------------------------------------------------------------------------

func createEventEvidencePod(
	name string,
	podLabels map[string]string,
) *corev1.Pod {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: controllerTestNamespace,
			Labels:    podLabels,
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
		k8sClient.Create(ctx, pod),
	).To(Succeed())

	return pod
}

func createEventEvidenceEvent(
	name string,
	pod *corev1.Pod,
	eventType string,
	reason string,
	action string,
	note string,
	eventTime time.Time,
	series *eventsv1.EventSeries,
) {
	event := &eventsv1.Event{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: pod.Namespace,
		},

		EventTime: metav1.NewMicroTime(
			eventTime,
		),

		Action: action,
		Reason: reason,

		Regarding: corev1.ObjectReference{
			APIVersion:      "v1",
			Kind:            "Pod",
			Namespace:       pod.Namespace,
			Name:            pod.Name,
			UID:             pod.UID,
			ResourceVersion: pod.ResourceVersion,
		},

		Note: note,
		Type: eventType,

		ReportingController: "kubetriage.test/kubelet",

		ReportingInstance: "kubetriage-test-instance",

		Series: series,
	}

	Expect(
		k8sClient.Create(ctx, event),
	).To(Succeed())
}

package controller

import (
	"context"
	"errors"
	"strings"
	"time"
	"unicode/utf8"

	opsv1alpha1 "github.com/yashshrivastav22/kubetriage/api/v1alpha1"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// -----------------------------------------------------------------------------
// Fake LogReader
// -----------------------------------------------------------------------------

type fakeLogReadCall struct {
	Namespace     string
	PodName       string
	ContainerName string
	Previous      bool
	TailLines     int64
	LimitBytes    int64
}

type fakeLogReader struct {
	CurrentData  []byte
	PreviousData []byte

	CurrentErr  error
	PreviousErr error

	Calls []fakeLogReadCall
}

func (f *fakeLogReader) ReadContainerLogs(
	ctx context.Context,
	namespace string,
	podName string,
	containerName string,
	previous bool,
	tailLines int64,
	limitBytes int64,
) ([]byte, error) {
	f.Calls = append(
		f.Calls,
		fakeLogReadCall{
			Namespace:     namespace,
			PodName:       podName,
			ContainerName: containerName,
			Previous:      previous,
			TailLines:     tailLines,
			LimitBytes:    limitBytes,
		},
	)

	if previous {
		if f.PreviousErr != nil {
			return nil, f.PreviousErr
		}

		return f.PreviousData, nil
	}

	if f.CurrentErr != nil {
		return nil, f.CurrentErr
	}

	return f.CurrentData, nil
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

var _ = Describe("Bounded container log evidence", func() {
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

	// ---------------------------------------------------------------------
	// TEST 1
	// Current and previous logs are collected with strict request limits.
	// ---------------------------------------------------------------------

	It("collects bounded current and previous container logs", func() {
		reader := &fakeLogReader{
			CurrentData: []byte(
				"current log line 1\ncurrent log line 2\n",
			),
			PreviousData: []byte(
				"previous crash log line 1\nprevious crash log line 2\n",
			),
		}

		finding := &incidentFinding{
			PodName:               "checkout-log-pod",
			PodUID:                "pod-uid-log-test",
			ContainerName:         "app",
			IncidentType:          "CrashLoopBackOff",
			RestartCount:          4,
			CurrentState:          "Waiting",
			WaitingReason:         "CrashLoopBackOff",
			LastTerminationReason: "Error",
		}

		reconciler := &IncidentPolicyReconciler{
			Client:    k8sClient,
			LogReader: reader,
		}

		evidence, err := reconciler.collectContainerLogEvidence(
			ctx,
			controllerTestNamespace,
			finding,
		)

		Expect(err).NotTo(HaveOccurred())

		Expect(evidence.CollectedAt).NotTo(BeNil())

		Expect(evidence.Current).To(
			Equal("current log line 1\ncurrent log line 2\n"),
		)

		Expect(evidence.Previous).To(
			Equal("previous crash log line 1\nprevious crash log line 2\n"),
		)

		Expect(evidence.CurrentTruncated).To(BeFalse())
		Expect(evidence.PreviousTruncated).To(BeFalse())

		// One current request + one previous request.
		Expect(reader.Calls).To(HaveLen(2))

		currentCall := reader.Calls[0]

		Expect(currentCall.Namespace).To(
			Equal(controllerTestNamespace),
		)
		Expect(currentCall.PodName).To(
			Equal("checkout-log-pod"),
		)
		Expect(currentCall.ContainerName).To(
			Equal("app"),
		)
		Expect(currentCall.Previous).To(BeFalse())
		Expect(currentCall.TailLines).To(
			Equal(incidentLogTailLines),
		)

		// Collector requests one additional byte so truncation can
		// be detected locally.
		Expect(currentCall.LimitBytes).To(
			Equal(incidentLogLimitBytes + 1),
		)

		previousCall := reader.Calls[1]

		Expect(previousCall.Previous).To(BeTrue())
		Expect(previousCall.TailLines).To(
			Equal(incidentLogTailLines),
		)
		Expect(previousCall.LimitBytes).To(
			Equal(incidentLogLimitBytes + 1),
		)
	})

	// ---------------------------------------------------------------------
	// TEST 2
	// Previous logs are not requested for a container that has never
	// restarted and has no known previous termination.
	// ---------------------------------------------------------------------

	It("does not request previous logs when no restart occurred", func() {
		reader := &fakeLogReader{
			CurrentData: []byte(
				"current application log",
			),
		}

		finding := &incidentFinding{
			PodName:       "image-pull-log-pod",
			PodUID:        "image-pull-pod-uid",
			ContainerName: "app",
			IncidentType:  "ImagePullBackOff",
			RestartCount:  0,
			CurrentState:  "Waiting",
			WaitingReason: "ImagePullBackOff",
		}

		reconciler := &IncidentPolicyReconciler{
			Client:    k8sClient,
			LogReader: reader,
		}

		evidence, err := reconciler.collectContainerLogEvidence(
			ctx,
			controllerTestNamespace,
			finding,
		)

		Expect(err).NotTo(HaveOccurred())

		Expect(evidence.Current).To(
			Equal("current application log"),
		)

		Expect(evidence.Previous).To(BeEmpty())

		Expect(reader.Calls).To(HaveLen(1))
		Expect(reader.Calls[0].Previous).To(BeFalse())
	})

	// ---------------------------------------------------------------------
	// TEST 3
	// Local storage limit is enforced and UTF-8 remains valid.
	// ---------------------------------------------------------------------

	It("truncates logs safely at the local byte limit", func() {
		// 16,383 ASCII bytes followed by a four-byte emoji.
		//
		// Cutting at 16,384 bytes would split the emoji. boundLogBytes()
		// should remove the incomplete UTF-8 bytes.
		rawLog := []byte(
			strings.Repeat(
				"a",
				int(incidentLogLimitBytes)-1,
			) + "🙂",
		)

		reader := &fakeLogReader{
			CurrentData: rawLog,
		}

		finding := &incidentFinding{
			PodName:       "large-log-pod",
			PodUID:        "large-log-pod-uid",
			ContainerName: "app",
			IncidentType:  "CrashLoopBackOff",
			CurrentState:  "Waiting",
			WaitingReason: "CrashLoopBackOff",
		}

		reconciler := &IncidentPolicyReconciler{
			Client:    k8sClient,
			LogReader: reader,
		}

		evidence, err := reconciler.collectContainerLogEvidence(
			ctx,
			controllerTestNamespace,
			finding,
		)

		Expect(err).NotTo(HaveOccurred())

		Expect(evidence.CurrentTruncated).To(BeTrue())

		Expect(
			utf8.ValidString(evidence.Current),
		).To(BeTrue())

		// The incomplete emoji bytes should have been removed.
		Expect(
			len([]byte(evidence.Current)),
		).To(Equal(int(incidentLogLimitBytes) - 1))

		Expect(
			strings.HasSuffix(
				evidence.Current,
				"a",
			),
		).To(BeTrue())
	})

	// ---------------------------------------------------------------------
	// TEST 4
	// A previous-log failure does not discard successfully collected
	// current logs.
	// ---------------------------------------------------------------------

	It("keeps current logs when previous log collection fails", func() {
		reader := &fakeLogReader{
			CurrentData: []byte(
				"current logs are available",
			),
			PreviousErr: errors.New(
				"previous container logs unavailable",
			),
		}

		finding := &incidentFinding{
			PodName:               "partial-log-failure-pod",
			PodUID:                "partial-log-failure-uid",
			ContainerName:         "app",
			IncidentType:          "CrashLoopBackOff",
			RestartCount:          3,
			CurrentState:          "Waiting",
			WaitingReason:         "CrashLoopBackOff",
			LastTerminationReason: "Error",
		}

		reconciler := &IncidentPolicyReconciler{
			Client:    k8sClient,
			LogReader: reader,
		}

		evidence, err := reconciler.collectContainerLogEvidence(
			ctx,
			controllerTestNamespace,
			finding,
		)

		// Partial collection returns useful evidence plus an error.
		Expect(err).To(HaveOccurred())

		Expect(err.Error()).To(
			ContainSubstring("previous"),
		)

		Expect(evidence.CollectedAt).NotTo(BeNil())

		Expect(evidence.Current).To(
			Equal("current logs are available"),
		)

		Expect(evidence.Previous).To(BeEmpty())

		Expect(reader.Calls).To(HaveLen(2))
	})

	// ---------------------------------------------------------------------
	// TEST 5
	// Total collection failure returns no new log evidence.
	// ---------------------------------------------------------------------

	It("returns no new log evidence when every requested log read fails", func() {
		reader := &fakeLogReader{
			CurrentErr: errors.New(
				"current log endpoint failed",
			),
			PreviousErr: errors.New(
				"previous log endpoint failed",
			),
		}

		finding := &incidentFinding{
			PodName:               "total-log-failure-pod",
			PodUID:                "total-log-failure-uid",
			ContainerName:         "app",
			IncidentType:          "CrashLoopBackOff",
			RestartCount:          5,
			CurrentState:          "Waiting",
			WaitingReason:         "CrashLoopBackOff",
			LastTerminationReason: "Error",
		}

		reconciler := &IncidentPolicyReconciler{
			Client:    k8sClient,
			LogReader: reader,
		}

		evidence, err := reconciler.collectContainerLogEvidence(
			ctx,
			controllerTestNamespace,
			finding,
		)

		Expect(err).To(HaveOccurred())

		Expect(evidence.CollectedAt).To(BeNil())
		Expect(evidence.Current).To(BeEmpty())
		Expect(evidence.Previous).To(BeEmpty())

		Expect(reader.Calls).To(HaveLen(2))
	})

	// ---------------------------------------------------------------------
	// TEST 6
	// Failure to collect logs must not prevent IncidentReport creation.
	// ---------------------------------------------------------------------

	It("creates an IncidentReport even when all log collection fails", func() {
		pod := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "log-failure-incident-pod",
				Namespace: controllerTestNamespace,
				Labels: map[string]string{
					"app": "log-failure-incident-test",
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
				RestartCount: 4,
				Image:        "busybox:1.36",
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
				Name:      "log-failure-incident-policy",
				Namespace: controllerTestNamespace,
			},
			Spec: opsv1alpha1.IncidentPolicySpec{
				Selector: metav1.LabelSelector{
					MatchLabels: map[string]string{
						"app": "log-failure-incident-test",
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

		reader := &fakeLogReader{
			CurrentErr: errors.New(
				"current logs unavailable",
			),
			PreviousErr: errors.New(
				"previous logs unavailable",
			),
		}

		reconciler := &IncidentPolicyReconciler{
			Client:    k8sClient,
			LogReader: reader,
		}

		result, err := reconciler.Reconcile(
			ctx,
			ctrl.Request{
				NamespacedName: types.NamespacedName{
					Name:      policy.Name,
					Namespace: policy.Namespace,
				},
			},
		)

		Expect(err).NotTo(HaveOccurred())

		Expect(result.RequeueAfter).To(
			Equal(30 * time.Second),
		)

		updatedPolicy := &opsv1alpha1.IncidentPolicy{}

		Expect(
			k8sClient.Get(
				ctx,
				types.NamespacedName{
					Name:      policy.Name,
					Namespace: policy.Namespace,
				},
				updatedPolicy,
			),
		).To(Succeed())

		condition := apimeta.FindStatusCondition(
			updatedPolicy.Status.Conditions,
			conditionTypeIncidentDetected,
		)

		Expect(condition).NotTo(BeNil())
		Expect(condition.Status).To(
			Equal(metav1.ConditionTrue),
		)
		Expect(condition.Reason).To(
			Equal("CrashLoopBackOffDetected"),
		)

		reports := &opsv1alpha1.IncidentReportList{}

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

		// Primary incident was still recorded.
		Expect(reports.Items).To(HaveLen(1))

		report := &reports.Items[0]

		Expect(report.Status.Phase).To(
			Equal("Active"),
		)

		Expect(report.Status.Evidence.Logs.Current).To(
			BeEmpty(),
		)
		Expect(report.Status.Evidence.Logs.Previous).To(
			BeEmpty(),
		)

		// Non-log evidence still exists.
		Expect(report.Status.Evidence.RestartCount).To(
			Equal(int32(4)),
		)
		Expect(report.Status.Evidence.WaitingReason).To(
			Equal("CrashLoopBackOff"),
		)
	})

	// ---------------------------------------------------------------------
	// TEST 7
	// Existing useful logs must survive a later temporary log API failure.
	// ---------------------------------------------------------------------

	It("preserves previously collected logs when a later collection attempt fails", func() {
		pod := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "preserve-log-pod",
				Namespace: controllerTestNamespace,
				Labels: map[string]string{
					"app": "preserve-log-test",
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
				RestartCount: 2,
				Image:        "busybox:1.36",
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
				Name:      "preserve-log-policy",
				Namespace: controllerTestNamespace,
			},
			Spec: opsv1alpha1.IncidentPolicySpec{
				Selector: metav1.LabelSelector{
					MatchLabels: map[string]string{
						"app": "preserve-log-test",
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

		reader := &fakeLogReader{
			CurrentData: []byte(
				"good current evidence",
			),
			PreviousData: []byte(
				"good previous evidence",
			),
		}

		reconciler := &IncidentPolicyReconciler{
			Client:    k8sClient,
			LogReader: reader,
		}

		// First reconcile succeeds in collecting logs.
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

		firstReports := &opsv1alpha1.IncidentReportList{}

		Expect(
			k8sClient.List(
				ctx,
				firstReports,
				client.InNamespace(
					controllerTestNamespace,
				),
				client.MatchingLabels{
					reportPolicyUIDLabel: string(policy.UID),
				},
			),
		).To(Succeed())

		Expect(firstReports.Items).To(HaveLen(1))

		firstLogs := firstReports.Items[0].Status.Evidence.Logs

		Expect(firstLogs.Current).To(
			Equal("good current evidence"),
		)
		Expect(firstLogs.Previous).To(
			Equal("good previous evidence"),
		)

		// Simulate a temporary log API failure.
		reader.CurrentData = nil
		reader.PreviousData = nil

		reader.CurrentErr = errors.New(
			"temporary current log failure",
		)
		reader.PreviousErr = errors.New(
			"temporary previous log failure",
		)

		// Same incident remains active.
		_, err = reconciler.Reconcile(
			ctx,
			ctrl.Request{
				NamespacedName: types.NamespacedName{
					Name:      policy.Name,
					Namespace: policy.Namespace,
				},
			},
		)

		Expect(err).NotTo(HaveOccurred())

		secondReports := &opsv1alpha1.IncidentReportList{}

		Expect(
			k8sClient.List(
				ctx,
				secondReports,
				client.InNamespace(
					controllerTestNamespace,
				),
				client.MatchingLabels{
					reportPolicyUIDLabel: string(policy.UID),
				},
			),
		).To(Succeed())

		Expect(secondReports.Items).To(HaveLen(1))

		secondLogs := secondReports.Items[0].Status.Evidence.Logs

		// Existing evidence must survive the failed refresh.
		Expect(secondLogs.Current).To(
			Equal("good current evidence"),
		)
		Expect(secondLogs.Previous).To(
			Equal("good previous evidence"),
		)
	})
})

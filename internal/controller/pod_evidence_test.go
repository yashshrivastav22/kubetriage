package controller

import (
	"strings"
	"time"

	opsv1alpha1 "github.com/yashshrivastav22/kubetriage/api/v1alpha1"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

var _ = Describe("Pod and container evidence", func() {
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

	It("collects rich evidence for an OOMKilled container", func() {
		startedAt := time.Date(2026, time.September, 27, 15, 0, 0, 0, time.UTC)
		finishedAt := startedAt.Add(45 * time.Second)

		pod := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "rich-oom-pod",
				Namespace: controllerTestNamespace,
			},
			Spec: corev1.PodSpec{
				NodeName: "worker-node-3",
				Containers: []corev1.Container{
					{
						Name:  "app",
						Image: "registry.example.com/checkout:v2.4.1",
					},
				},
			},
		}

		Expect(k8sClient.Create(ctx, pod)).To(Succeed())

		pod.Status.ContainerStatuses = []corev1.ContainerStatus{
			{
				Name:         "app",
				RestartCount: 4,
				Image:        "registry.example.com/checkout:v2.4.1",
				ImageID:      "containerd://sha256:deadbeef",
				ContainerID:  "containerd://running123",
				State: corev1.ContainerState{
					Running: &corev1.ContainerStateRunning{},
				},
				LastTerminationState: corev1.ContainerState{
					Terminated: &corev1.ContainerStateTerminated{
						ExitCode:    137,
						Signal:      9,
						Reason:      "OOMKilled",
						Message:     "memory cgroup limit exceeded",
						StartedAt:   metav1.NewTime(startedAt),
						FinishedAt:  metav1.NewTime(finishedAt),
						ContainerID: "containerd://terminated456",
					},
				},
			},
		}

		Expect(k8sClient.Status().Update(ctx, pod)).To(Succeed())

		exitCode := int32(137)

		finding := &incidentFinding{
			PodName:               pod.Name,
			PodUID:                string(pod.UID),
			ContainerName:         "app",
			IncidentType:          "OOMKilled",
			RestartCount:          4,
			CurrentState:          "Running",
			LastTerminationReason: "OOMKilled",
			ExitCode:              &exitCode,
		}

		reconciler := &IncidentPolicyReconciler{
			Client: k8sClient,
		}

		evidence, err := reconciler.collectPodContainerEvidence(
			ctx,
			controllerTestNamespace,
			finding,
		)

		Expect(err).NotTo(HaveOccurred())

		Expect(evidence.NodeName).To(Equal("worker-node-3"))
		Expect(evidence.ConfiguredImage).To(
			Equal("registry.example.com/checkout:v2.4.1"),
		)
		Expect(evidence.RuntimeImage).To(
			Equal("registry.example.com/checkout:v2.4.1"),
		)
		Expect(evidence.ImageID).To(
			Equal("containerd://sha256:deadbeef"),
		)
		Expect(evidence.ContainerID).To(
			Equal("containerd://terminated456"),
		)
		Expect(evidence.RestartCount).To(Equal(int32(4)))
		Expect(evidence.CurrentState).To(Equal("Running"))
		Expect(evidence.LastTerminationReason).To(Equal("OOMKilled"))
		Expect(evidence.WaitingReason).To(BeEmpty())

		Expect(evidence.ExitCode).NotTo(BeNil())
		Expect(*evidence.ExitCode).To(Equal(int32(137)))

		Expect(evidence.Signal).NotTo(BeNil())
		Expect(*evidence.Signal).To(Equal(int32(9)))

		Expect(evidence.TerminationStartedAt).NotTo(BeNil())
		Expect(
			evidence.TerminationStartedAt.Time.Equal(startedAt),
		).To(BeTrue())

		Expect(evidence.TerminationFinishedAt).NotTo(BeNil())
		Expect(
			evidence.TerminationFinishedAt.Time.Equal(finishedAt),
		).To(BeTrue())

		Expect(evidence.TerminationMessage).To(
			Equal("memory cgroup limit exceeded"),
		)
	})

	It("truncates long termination messages without breaking Unicode", func() {
		longMessage := strings.Repeat(
			"🙂",
			maxTerminationMessageRunes+100,
		)

		pod := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "long-termination-message-pod",
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

		Expect(k8sClient.Create(ctx, pod)).To(Succeed())

		pod.Status.ContainerStatuses = []corev1.ContainerStatus{
			{
				Name:        "app",
				Image:       "busybox:1.36",
				ImageID:     "containerd://sha256:message-test",
				ContainerID: "containerd://message-test",
				State: corev1.ContainerState{
					Terminated: &corev1.ContainerStateTerminated{
						ExitCode: 1,
						Reason:   "Error",
						Message:  longMessage,
					},
				},
			},
		}

		Expect(k8sClient.Status().Update(ctx, pod)).To(Succeed())

		finding := &incidentFinding{
			PodName:       pod.Name,
			PodUID:        string(pod.UID),
			ContainerName: "app",
			IncidentType:  "CrashLoopBackOff",
		}

		reconciler := &IncidentPolicyReconciler{
			Client: k8sClient,
		}

		evidence, err := reconciler.collectPodContainerEvidence(
			ctx,
			controllerTestNamespace,
			finding,
		)

		Expect(err).NotTo(HaveOccurred())

		messageRunes := []rune(evidence.TerminationMessage)

		Expect(
			messageRunes,
		).To(HaveLen(maxTerminationMessageRunes))

		Expect(
			string(messageRunes[len(messageRunes)-1]),
		).To(Equal("🙂"))
	})

	It("rejects evidence from a replacement Pod with the same name but a different UID", func() {
		pod := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "uid-protection-pod",
				Namespace: controllerTestNamespace,
			},
			Spec: corev1.PodSpec{
				NodeName: "worker-replacement",
				Containers: []corev1.Container{
					{
						Name:  "app",
						Image: "busybox:1.36",
					},
				},
			},
		}

		Expect(k8sClient.Create(ctx, pod)).To(Succeed())

		finding := &incidentFinding{
			PodName:       pod.Name,
			PodUID:        "different-pod-uid",
			ContainerName: "app",
			IncidentType:  "CrashLoopBackOff",
			RestartCount:  3,
			CurrentState:  "Waiting",
			WaitingReason: "CrashLoopBackOff",
		}

		reconciler := &IncidentPolicyReconciler{
			Client: k8sClient,
		}

		evidence, err := reconciler.collectPodContainerEvidence(
			ctx,
			controllerTestNamespace,
			finding,
		)

		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(
			ContainSubstring("pod UID changed"),
		)

		Expect(evidence.RestartCount).To(Equal(int32(3)))
		Expect(evidence.CurrentState).To(Equal("Waiting"))
		Expect(evidence.WaitingReason).To(Equal("CrashLoopBackOff"))

		Expect(evidence.NodeName).To(BeEmpty())
		Expect(evidence.ConfiguredImage).To(BeEmpty())
	})

	It("stores rich OOMKilled evidence in IncidentReport status", func() {
		startedAt := time.Date(2026, time.September, 27, 16, 0, 0, 0, time.UTC)
		finishedAt := startedAt.Add(20 * time.Second)

		pod := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "report-rich-oom-pod",
				Namespace: controllerTestNamespace,
				Labels: map[string]string{
					"app": "report-rich-oom-test",
				},
			},
			Spec: corev1.PodSpec{
				NodeName: "worker-rich-oom",
				Containers: []corev1.Container{
					{
						Name:  "app",
						Image: "registry.example.com/checkout:v3.0.0",
					},
				},
			},
		}

		Expect(k8sClient.Create(ctx, pod)).To(Succeed())

		pod.Status.ContainerStatuses = []corev1.ContainerStatus{
			{
				Name:         "app",
				RestartCount: 8,
				Image:        "registry.example.com/checkout:v3.0.0",
				ImageID:      "containerd://sha256:abc123",
				ContainerID:  "containerd://running777",
				State: corev1.ContainerState{
					Running: &corev1.ContainerStateRunning{},
				},
				LastTerminationState: corev1.ContainerState{
					Terminated: &corev1.ContainerStateTerminated{
						ExitCode:    137,
						Signal:      9,
						Reason:      "OOMKilled",
						Message:     "container exceeded its memory limit",
						StartedAt:   metav1.NewTime(startedAt),
						FinishedAt:  metav1.NewTime(finishedAt),
						ContainerID: "containerd://failed999",
					},
				},
			},
		}

		Expect(k8sClient.Status().Update(ctx, pod)).To(Succeed())

		policy := &opsv1alpha1.IncidentPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "report-rich-oom-policy",
				Namespace: controllerTestNamespace,
			},
			Spec: opsv1alpha1.IncidentPolicySpec{
				Selector: metav1.LabelSelector{
					MatchLabels: map[string]string{
						"app": "report-rich-oom-test",
					},
				},
				Checks: opsv1alpha1.IncidentChecks{
					OOMKilled: true,
				},
			},
		}

		Expect(k8sClient.Create(ctx, policy)).To(Succeed())

		reconcilePolicy(policy.Name)

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
		evidence := report.Status.Evidence

		Expect(report.Status.Phase).To(Equal("Active"))
		Expect(report.Spec.IncidentType).To(Equal("OOMKilled"))

		Expect(evidence.NodeName).To(Equal("worker-rich-oom"))
		Expect(evidence.ConfiguredImage).To(
			Equal("registry.example.com/checkout:v3.0.0"),
		)
		Expect(evidence.RuntimeImage).To(
			Equal("registry.example.com/checkout:v3.0.0"),
		)
		Expect(evidence.ImageID).To(
			Equal("containerd://sha256:abc123"),
		)
		Expect(evidence.ContainerID).To(
			Equal("containerd://failed999"),
		)

		Expect(evidence.RestartCount).To(Equal(int32(8)))
		Expect(evidence.CurrentState).To(Equal("Running"))
		Expect(evidence.LastTerminationReason).To(Equal("OOMKilled"))

		Expect(evidence.ExitCode).NotTo(BeNil())
		Expect(*evidence.ExitCode).To(Equal(int32(137)))

		Expect(evidence.Signal).NotTo(BeNil())
		Expect(*evidence.Signal).To(Equal(int32(9)))

		Expect(evidence.TerminationStartedAt).NotTo(BeNil())
		Expect(
			evidence.TerminationStartedAt.Time.Equal(startedAt),
		).To(BeTrue())

		Expect(evidence.TerminationFinishedAt).NotTo(BeNil())
		Expect(
			evidence.TerminationFinishedAt.Time.Equal(finishedAt),
		).To(BeTrue())

		Expect(evidence.TerminationMessage).To(
			Equal("container exceeded its memory limit"),
		)
	})
})

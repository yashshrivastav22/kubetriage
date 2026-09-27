package controller

import (
	"context"
	"fmt"
	"io"
	"unicode/utf8"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

const (
	incidentLogTailLines  int64 = 50
	incidentLogLimitBytes int64 = 16 * 1024
)

// LogReader abstracts access to the Kubernetes Pod log subresource.
//
// Production uses kubernetesLogReader.
// Tests will use a fake implementation so envtest does not require kubelet.
type LogReader interface {
	ReadContainerLogs(
		ctx context.Context,
		namespace string,
		podName string,
		containerName string,
		previous bool,
		tailLines int64,
		limitBytes int64,
	) ([]byte, error)
}

// kubernetesLogReader reads Pod logs through the Kubernetes API.
type kubernetesLogReader struct {
	client kubernetes.Interface
}

// newKubernetesLogReader creates the production log reader.
func newKubernetesLogReader(
	config *rest.Config,
) (LogReader, error) {
	if config == nil {
		return nil, fmt.Errorf(
			"kubernetes REST config is nil",
		)
	}

	clientset, err := kubernetes.NewForConfig(
		config,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"create Kubernetes clientset: %w",
			err,
		)
	}

	return &kubernetesLogReader{
		client: clientset,
	}, nil
}

// ReadContainerLogs requests a bounded log tail for one container.
func (r *kubernetesLogReader) ReadContainerLogs(
	ctx context.Context,
	namespace string,
	podName string,
	containerName string,
	previous bool,
	tailLines int64,
	limitBytes int64,
) ([]byte, error) {
	if namespace == "" {
		return nil, fmt.Errorf(
			"namespace is required",
		)
	}

	if podName == "" {
		return nil, fmt.Errorf(
			"pod name is required",
		)
	}

	if containerName == "" {
		return nil, fmt.Errorf(
			"container name is required",
		)
	}

	if tailLines <= 0 {
		return nil, fmt.Errorf(
			"tailLines must be greater than zero",
		)
	}

	if limitBytes <= 0 {
		return nil, fmt.Errorf(
			"limitBytes must be greater than zero",
		)
	}

	request := r.client.
		CoreV1().
		Pods(namespace).
		GetLogs(
			podName,
			&corev1.PodLogOptions{
				Container:  containerName,
				Previous:   previous,
				TailLines:  &tailLines,
				LimitBytes: &limitBytes,
			},
		)

	stream, err := request.Stream(ctx)
	if err != nil {
		return nil, fmt.Errorf(
			"open Pod log stream: %w",
			err,
		)
	}
	defer stream.Close()

	// Kubernetes already receives LimitBytes, but we enforce the limit
	// locally as well.
	//
	// Read one extra byte so KubeTriage can detect truncation.
	data, err := io.ReadAll(
		io.LimitReader(
			stream,
			limitBytes+1,
		),
	)
	if err != nil {
		return nil, fmt.Errorf(
			"read Pod log stream: %w",
			err,
		)
	}

	return data, nil
}

// boundLogBytes converts a raw log response into a valid UTF-8 string
// while enforcing KubeTriage's local storage limit.
//
// The returned bool indicates whether truncation occurred.
func boundLogBytes(
	data []byte,
	limit int,
) (string, bool) {
	if limit <= 0 {
		return "", len(data) > 0
	}

	truncated := len(data) > limit

	if truncated {
		data = data[:limit]
	}

	// A byte-based limit can split a multi-byte UTF-8 character.
	// Remove incomplete trailing bytes before converting to string.
	for len(data) > 0 && !utf8.Valid(data) {
		data = data[:len(data)-1]
	}

	return string(data), truncated
}

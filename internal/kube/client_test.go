package kube

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestFetchListsNodesAndPodsInEveryNamespace(t *testing.T) {
	cs := fake.NewSimpleClientset(
		&corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "worker-1"}},
		&corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "worker-2"}},
		&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "api", Namespace: "default"}},
		&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "agent", Namespace: "monitoring"}},
	)

	nodes, pods, err := Fetch(context.Background(), cs)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if len(nodes) != 2 {
		t.Errorf("nodes = %d, want 2", len(nodes))
	}
	if len(pods) != 2 {
		t.Errorf("pods = %d, want 2 across namespaces", len(pods))
	}
}

func TestFetchOnEmptyClusterIsNotAnError(t *testing.T) {
	nodes, pods, err := Fetch(context.Background(), fake.NewSimpleClientset())
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if len(nodes) != 0 || len(pods) != 0 {
		t.Errorf("got %d nodes and %d pods, want none", len(nodes), len(pods))
	}
}

func TestClientFailsOnAMissingKubeconfig(t *testing.T) {
	t.Setenv("KUBERNETES_SERVICE_HOST", "")
	if _, err := Client("/nonexistent/kubeconfig", ""); err == nil {
		t.Error("want an error for a kubeconfig path that does not exist")
	}
}

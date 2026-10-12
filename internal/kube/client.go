// Package kube is the thin adapter between the cluster and the rule engine: it
// builds a client from a kubeconfig and lists nodes and pods. No rule logic
// lives here, which is why the engine needs no cluster to be tested.
package kube

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

// Client builds a clientset from the usual kubeconfig resolution rules:
// an explicit path wins, then $KUBECONFIG, then ~/.kube/config, then the
// in-cluster service account. An empty contextName keeps the current context.
func Client(kubeconfig, contextName string) (*kubernetes.Clientset, error) {
	rules := clientcmd.NewDefaultClientConfigLoadingRules()
	if kubeconfig != "" {
		rules.ExplicitPath = kubeconfig
	}
	overrides := &clientcmd.ConfigOverrides{}
	if contextName != "" {
		overrides.CurrentContext = contextName
	}
	cfg, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(rules, overrides).ClientConfig()
	if err != nil {
		return nil, fmt.Errorf("load kubeconfig: %w", err)
	}
	cs, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("build client: %w", err)
	}
	return cs, nil
}

// Fetch lists every node and every pod in the cluster. It takes the interface
// rather than the concrete clientset so a fake can stand in during tests.
// Required RBAC is read-only: get/list on nodes and pods.
func Fetch(ctx context.Context, cs kubernetes.Interface) ([]corev1.Node, []corev1.Pod, error) {
	nodes, err := cs.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, nil, fmt.Errorf("list nodes: %w", err)
	}
	pods, err := cs.CoreV1().Pods(metav1.NamespaceAll).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, nil, fmt.Errorf("list pods: %w", err)
	}
	return nodes.Items, pods.Items, nil
}

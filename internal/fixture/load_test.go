package fixture

import (
	"os"
	"path/filepath"
	"testing"
)

func write(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "snapshot.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	return path
}

func TestLoadList(t *testing.T) {
	path := write(t, `apiVersion: v1
kind: List
items:
  - apiVersion: v1
    kind: Node
    metadata:
      name: worker-1
    spec:
      taints:
        - key: spot
          value: "true"
          effect: NoSchedule
  - apiVersion: v1
    kind: Pod
    metadata:
      name: api
      namespace: default
    spec:
      tolerations:
        - key: spot
          operator: Exists
`)

	nodes, pods, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(nodes) != 1 || nodes[0].Name != "worker-1" {
		t.Fatalf("nodes = %+v, want one worker-1", nodes)
	}
	if len(nodes[0].Spec.Taints) != 1 || nodes[0].Spec.Taints[0].Key != "spot" {
		t.Errorf("taints = %+v, want one spot taint", nodes[0].Spec.Taints)
	}
	if len(pods) != 1 || pods[0].Name != "api" {
		t.Fatalf("pods = %+v, want one api pod", pods)
	}
	if len(pods[0].Spec.Tolerations) != 1 {
		t.Errorf("tolerations = %+v, want one", pods[0].Spec.Tolerations)
	}
}

func TestLoadMultiDocumentAndIgnoresOtherKinds(t *testing.T) {
	path := write(t, `apiVersion: v1
kind: Node
metadata:
  name: worker-1
---
apiVersion: v1
kind: Pod
metadata:
  name: api
  namespace: default
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: not-interesting
`)

	nodes, pods, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(nodes) != 1 || len(pods) != 1 {
		t.Fatalf("got %d nodes and %d pods, want 1 and 1", len(nodes), len(pods))
	}
}

func TestLoadRejectsEmptyAndMissing(t *testing.T) {
	if _, _, err := Load(write(t, "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: x\n")); err == nil {
		t.Error("want an error when a snapshot has no nodes or pods")
	}
	if _, _, err := Load(filepath.Join(t.TempDir(), "absent.yaml")); err == nil {
		t.Error("want an error for a missing file")
	}
}

func TestLoadBundledExample(t *testing.T) {
	nodes, pods, err := Load(filepath.Join("..", "..", "examples", "cluster.yaml"))
	if err != nil {
		t.Fatalf("Load example: %v", err)
	}
	if len(nodes) != 3 {
		t.Errorf("example nodes = %d, want 3", len(nodes))
	}
	if len(pods) != 5 {
		t.Errorf("example pods = %d, want 5", len(pods))
	}
}

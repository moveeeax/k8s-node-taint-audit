// Package fixture loads nodes and pods from a YAML or JSON file so the audit
// can run against a captured cluster snapshot. This is what makes the examples
// reproducible and what lets CI assert on real output with no cluster around.
package fixture

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/yaml"
)

type meta struct {
	Kind  string            `json:"kind"`
	Items []json.RawMessage `json:"items"`
}

// Load reads a file of Kubernetes objects: a List, a stream of `---` separated
// documents, or a single object. Node and Pod objects are kept, anything else
// is ignored so a plain `kubectl get nodes,pods -o yaml` dump works as is.
func Load(path string) ([]corev1.Node, []corev1.Pod, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	var nodes []corev1.Node
	var pods []corev1.Pod
	for _, doc := range splitDocs(string(raw)) {
		jsonDoc, err := yaml.YAMLToJSON([]byte(doc))
		if err != nil {
			return nil, nil, fmt.Errorf("%s: %w", path, err)
		}
		if err := collect(jsonDoc, &nodes, &pods); err != nil {
			return nil, nil, fmt.Errorf("%s: %w", path, err)
		}
	}
	if len(nodes) == 0 && len(pods) == 0 {
		return nil, nil, fmt.Errorf("%s: no Node or Pod objects found", path)
	}
	return nodes, pods, nil
}

func collect(doc []byte, nodes *[]corev1.Node, pods *[]corev1.Pod) error {
	var m meta
	if err := json.Unmarshal(doc, &m); err != nil {
		return err
	}
	if m.Items != nil {
		for _, item := range m.Items {
			if err := collect(item, nodes, pods); err != nil {
				return err
			}
		}
		return nil
	}
	switch m.Kind {
	case "Node":
		var n corev1.Node
		if err := json.Unmarshal(doc, &n); err != nil {
			return err
		}
		*nodes = append(*nodes, n)
	case "Pod":
		var p corev1.Pod
		if err := json.Unmarshal(doc, &p); err != nil {
			return err
		}
		*pods = append(*pods, p)
	}
	return nil
}

func splitDocs(s string) []string {
	var out []string
	for _, doc := range strings.Split(s, "\n---") {
		if strings.TrimSpace(strings.TrimLeft(doc, "-\n")) != "" {
			out = append(out, doc)
		}
	}
	return out
}

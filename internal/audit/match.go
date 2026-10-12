package audit

import (
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
)

// builtinPrefixes are the taint keys the control plane sets and clears by
// itself. DefaultTolerationSeconds also injects tolerations for not-ready and
// unreachable into nearly every pod, so counting these keys as orphans or as
// stranded capacity reports normal cluster behaviour as a problem.
var builtinPrefixes = []string{
	"node.kubernetes.io/",
	"node.cloudprovider.kubernetes.io/",
}

// IsBuiltinKey reports whether a taint or toleration key is control-plane managed.
func IsBuiltinKey(key string) bool {
	for _, p := range builtinPrefixes {
		if strings.HasPrefix(key, p) {
			return true
		}
	}
	return false
}

// Tolerates implements the scheduler's matching rules for one toleration
// against one taint: an empty effect matches every effect, an empty key with
// operator Exists matches every key, Exists ignores the value, and Equal (the
// default when operator is unset) requires an exact value match.
func Tolerates(tol corev1.Toleration, taint corev1.Taint) bool {
	if tol.Effect != "" && tol.Effect != taint.Effect {
		return false
	}
	if tol.Key != "" && tol.Key != taint.Key {
		return false
	}
	switch tol.Operator {
	case corev1.TolerationOpExists:
		return true
	case corev1.TolerationOpEqual, "":
		return tol.Value == taint.Value
	default:
		return false
	}
}

// IsBlanket reports whether a toleration is the catch-all form: an empty key
// with operator Exists, which matches every taint there is.
func IsBlanket(tol corev1.Toleration) bool {
	return tol.Key == "" && tol.Operator == corev1.TolerationOpExists
}

// PodTolerates reports whether any of the pod's tolerations matches the taint.
func PodTolerates(pod *corev1.Pod, taint corev1.Taint) bool {
	for _, tol := range pod.Spec.Tolerations {
		if Tolerates(tol, taint) {
			return true
		}
	}
	return false
}

// PodTolerationKind classifies how a pod tolerates a taint. specific means at
// least one toleration names the taint's key (or carries a key that matches),
// blanket means the only match came from a catch-all toleration. The split
// matters: with one catch-all DaemonSet in the cluster, counting it as a
// tolerating workload would make the unused-taint rule unable to ever fire.
func PodTolerationKind(pod *corev1.Pod, taint corev1.Taint) (specific, blanket bool) {
	for _, tol := range pod.Spec.Tolerations {
		if !Tolerates(tol, taint) {
			continue
		}
		if IsBlanket(tol) {
			blanket = true
			continue
		}
		specific = true
	}
	return specific, blanket
}

// taintSelector is a parsed --ignore-taint argument. A missing value or effect
// means "any", so `dedicated` ignores the key whatever it carries.
type taintSelector struct {
	key      string
	value    string
	hasValue bool
	effect   string
}

func parseTaintSelector(s string) (taintSelector, error) {
	raw := strings.TrimSpace(s)
	if raw == "" {
		return taintSelector{}, fmt.Errorf("empty taint selector")
	}
	sel := taintSelector{}
	if i := strings.Index(raw, ":"); i >= 0 {
		sel.effect = raw[i+1:]
		raw = raw[:i]
		switch sel.effect {
		case string(corev1.TaintEffectNoSchedule), string(corev1.TaintEffectPreferNoSchedule), string(corev1.TaintEffectNoExecute):
		default:
			return taintSelector{}, fmt.Errorf("unknown taint effect %q (want NoSchedule, PreferNoSchedule or NoExecute)", sel.effect)
		}
	}
	if i := strings.Index(raw, "="); i >= 0 {
		sel.key, sel.value, sel.hasValue = raw[:i], raw[i+1:], true
	} else {
		sel.key = raw
	}
	if sel.key == "" {
		return taintSelector{}, fmt.Errorf("taint selector %q has no key", s)
	}
	return sel, nil
}

func (sel taintSelector) matches(t corev1.Taint) bool {
	if sel.key != t.Key {
		return false
	}
	if sel.hasValue && sel.value != t.Value {
		return false
	}
	if sel.effect != "" && sel.effect != string(t.Effect) {
		return false
	}
	return true
}

// parseSelectors turns raw CLI arguments into selectors. Comma-separated lists
// inside one argument are accepted so --ignore-taint a=b,c=d works.
func parseSelectors(args []string) ([]taintSelector, error) {
	var out []taintSelector
	for _, arg := range args {
		before := len(out)
		for _, part := range strings.Split(arg, ",") {
			if strings.TrimSpace(part) == "" {
				continue
			}
			sel, err := parseTaintSelector(part)
			if err != nil {
				return nil, err
			}
			out = append(out, sel)
		}
		// A blank entry inside a list is tolerated, but a flag that parsed to
		// nothing at all is a typo worth failing on rather than ignoring.
		if len(out) == before {
			return nil, fmt.Errorf("empty taint selector %q", arg)
		}
	}
	return out, nil
}

// WorkloadOf names the controller behind a pod, so a 60-replica DaemonSet
// counts as one tolerating workload instead of sixty. A ReplicaSet is folded
// back into its Deployment by dropping the pod-template hash.
func WorkloadOf(pod *corev1.Pod) string {
	for _, ref := range pod.OwnerReferences {
		if ref.Controller == nil || !*ref.Controller {
			continue
		}
		if ref.Kind == "ReplicaSet" {
			if i := strings.LastIndex(ref.Name, "-"); i > 0 {
				return "Deployment/" + ref.Name[:i]
			}
		}
		return ref.Kind + "/" + ref.Name
	}
	return "Pod/" + pod.Name
}

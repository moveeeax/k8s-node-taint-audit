// Package audit holds the taint/toleration rule engine. It is deliberately free
// of any Kubernetes client code: Analyze takes plain API objects and returns
// findings, so every rule is unit-testable without a cluster.
package audit

import (
	corev1 "k8s.io/api/core/v1"
)

// Rule identifies one check. The string form is what --fail-on matches and what
// lands in the JSON output, so these values are part of the CLI contract.
type Rule string

const (
	// RuleUnusedTaint fires for a node taint that no pod in the cluster tolerates.
	RuleUnusedTaint Rule = "unused-taint"
	// RuleOrphanToleration fires for a toleration whose key is on no node taint.
	RuleOrphanToleration Rule = "orphan-toleration"
	// RuleBlanketToleration fires for a toleration with an empty key and operator Exists.
	RuleBlanketToleration Rule = "blanket-toleration"
	// RuleNoExecuteForever fires for a NoExecute toleration with no tolerationSeconds.
	RuleNoExecuteForever Rule = "noexecute-forever"
)

// AllRules lists every rule in report order.
func AllRules() []Rule {
	return []Rule{RuleBlanketToleration, RuleNoExecuteForever, RuleUnusedTaint, RuleOrphanToleration}
}

// ValidRule reports whether s names a known rule.
func ValidRule(s string) bool {
	for _, r := range AllRules() {
		if string(r) == s {
			return true
		}
	}
	return false
}

// Options tunes Analyze.
type Options struct {
	// IgnoreTaints holds taint selectors ("key", "key=value", "key=value:Effect",
	// "key:Effect") that are known-good and must not produce unused-taint findings.
	IgnoreTaints []string
	// IncludeBuiltin includes the node.kubernetes.io/ and
	// node.cloudprovider.kubernetes.io/ taint keys that the control plane and the
	// DefaultTolerationSeconds admission plugin manage on their own. Off by
	// default: those keys are transient by design and drown the report.
	IncludeBuiltin bool
}

// Finding is one rule hit. Empty fields are omitted from JSON so a node finding
// does not carry blank pod keys and vice versa.
type Finding struct {
	Rule     Rule   `json:"rule"`
	Severity string `json:"severity"`

	Node      string `json:"node,omitempty"`
	Namespace string `json:"namespace,omitempty"`
	Pod       string `json:"pod,omitempty"`
	Workload  string `json:"workload,omitempty"`

	// Taint is the rendered "key=value:Effect" form of the taint involved.
	Taint string `json:"taint,omitempty"`
	// TolerationKey is the toleration key involved, where the finding is about a pod.
	TolerationKey string `json:"tolerationKey,omitempty"`
	// Effect carries the toleration or taint effect when it is the point of the finding.
	Effect string `json:"effect,omitempty"`

	AllocatableCPU    string `json:"allocatableCpu,omitempty"`
	AllocatableMemory string `json:"allocatableMemory,omitempty"`

	Message string `json:"message"`
}

// Object renders the thing a finding is about, for the table output.
func (f Finding) Object() string {
	if f.Pod != "" {
		return f.Namespace + "/" + f.Pod
	}
	if f.Node != "" {
		return "node/" + f.Node
	}
	return "-"
}

// TaintView is one taint on one node plus how much of the cluster tolerates it.
type TaintView struct {
	Key    string `json:"key"`
	Value  string `json:"value,omitempty"`
	Effect string `json:"effect"`
	// Taint is the rendered "key=value:Effect" form.
	Taint string `json:"taint"`
	// TolerantPods counts pods that match this taint with a toleration naming
	// its key. Catch-all tolerations are counted separately on purpose.
	TolerantPods int `json:"tolerantPods"`
	// TolerantWorkloads counts distinct owning workloads behind those pods.
	TolerantWorkloads int `json:"tolerantWorkloads"`
	// BlanketPods counts pods that match only through a catch-all toleration
	// (empty key, operator Exists). They are not evidence that the taint is in
	// use: a node-exporter DaemonSet tolerates every taint in the cluster.
	BlanketPods int `json:"blanketPods,omitempty"`
	// BlanketWorkloads counts distinct workloads behind BlanketPods.
	BlanketWorkloads int `json:"blanketWorkloads,omitempty"`
	// Ignored is true when --ignore-taint covers this taint.
	Ignored bool `json:"ignored,omitempty"`
	// Builtin is true for control-plane managed taint keys.
	Builtin bool `json:"builtin,omitempty"`
}

// NodeView is the per-node picture: taints and the capacity sitting behind them.
type NodeView struct {
	Name              string      `json:"name"`
	AllocatableCPU    string      `json:"allocatableCpu"`
	AllocatableMemory string      `json:"allocatableMemory"`
	Taints            []TaintView `json:"taints"`
}

// Report is the full result of one audit run.
type Report struct {
	NodesTotal     int            `json:"nodesTotal"`
	PodsTotal      int            `json:"podsTotal"`
	TaintedNodes   int            `json:"taintedNodes"`
	Nodes          []NodeView     `json:"nodes"`
	Findings       []Finding      `json:"findings"`
	Summary        map[string]int `json:"summary"`
	StrandedCPU    string         `json:"strandedCpu"`
	StrandedMemory string         `json:"strandedMemory"`
}

// Count returns how many findings fired for a rule.
func (r Report) Count(rule Rule) int {
	return r.Summary[string(rule)]
}

// Fired reports whether any of the named rules produced a finding.
func (r Report) Fired(rules []Rule) bool {
	for _, rule := range rules {
		if r.Summary[string(rule)] > 0 {
			return true
		}
	}
	return false
}

var severities = map[Rule]string{
	RuleBlanketToleration: "high",
	RuleNoExecuteForever:  "medium",
	RuleUnusedTaint:       "medium",
	RuleOrphanToleration:  "low",
}

// TaintString renders a taint the way kubectl taint accepts it.
func TaintString(t corev1.Taint) string {
	s := t.Key
	if t.Value != "" {
		s += "=" + t.Value
	}
	if t.Effect != "" {
		s += ":" + string(t.Effect)
	}
	return s
}

package audit

import (
	"bytes"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func node(name string, taints ...corev1.Taint) corev1.Node {
	return corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec:       corev1.NodeSpec{Taints: taints},
		Status: corev1.NodeStatus{Allocatable: corev1.ResourceList{
			corev1.ResourceCPU:    resource.MustParse("16"),
			corev1.ResourceMemory: resource.MustParse("64Gi"),
		}},
	}
}

func taint(key, value string, effect corev1.TaintEffect) corev1.Taint {
	return corev1.Taint{Key: key, Value: value, Effect: effect}
}

func pod(name string, tols ...corev1.Toleration) corev1.Pod {
	return corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "default"},
		Spec:       corev1.PodSpec{Tolerations: tols},
	}
}

func owned(p corev1.Pod, kind, owner string) corev1.Pod {
	yes := true
	p.OwnerReferences = []metav1.OwnerReference{{Kind: kind, Name: owner, Controller: &yes}}
	return p
}

func seconds(n int64) *int64 { return &n }

// findingsFor returns every finding of one rule, so a test can assert on count
// and content without caring about the other rules.
func findingsFor(t *testing.T, rep Report, rule Rule) []Finding {
	t.Helper()
	var out []Finding
	for _, f := range rep.Findings {
		if f.Rule == rule {
			out = append(out, f)
		}
	}
	if len(out) != rep.Count(rule) {
		t.Fatalf("summary says %s=%d but %d findings carry that rule", rule, rep.Count(rule), len(out))
	}
	return out
}

func analyze(t *testing.T, nodes []corev1.Node, pods []corev1.Pod, opts Options) Report {
	t.Helper()
	rep, err := Analyze(nodes, pods, opts)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	return rep
}

func TestUnusedTaintNamesNodeTaintAndCapacity(t *testing.T) {
	nodes := []corev1.Node{node("gpu-1", taint("dedicated", "gpu", corev1.TaintEffectNoSchedule))}
	pods := []corev1.Pod{pod("web")}

	rep := analyze(t, nodes, pods, Options{})

	got := findingsFor(t, rep, RuleUnusedTaint)
	if len(got) != 1 {
		t.Fatalf("want 1 unused-taint finding, got %d", len(got))
	}
	f := got[0]
	if f.Node != "gpu-1" {
		t.Errorf("node = %q, want gpu-1", f.Node)
	}
	if f.Taint != "dedicated=gpu:NoSchedule" {
		t.Errorf("taint = %q, want dedicated=gpu:NoSchedule", f.Taint)
	}
	if f.AllocatableCPU != "16" || f.AllocatableMemory != "64Gi" {
		t.Errorf("allocatable = %q/%q, want 16/64Gi", f.AllocatableCPU, f.AllocatableMemory)
	}
	if rep.StrandedCPU != "16" || rep.StrandedMemory != "64Gi" {
		t.Errorf("stranded = %q/%q, want 16/64Gi", rep.StrandedCPU, rep.StrandedMemory)
	}
}

func TestToleratedTaintIsNotUnused(t *testing.T) {
	nodes := []corev1.Node{node("gpu-1", taint("dedicated", "gpu", corev1.TaintEffectNoSchedule))}
	pods := []corev1.Pod{pod("trainer", corev1.Toleration{
		Key: "dedicated", Operator: corev1.TolerationOpEqual, Value: "gpu", Effect: corev1.TaintEffectNoSchedule,
	})}

	rep := analyze(t, nodes, pods, Options{})

	if n := rep.Count(RuleUnusedTaint); n != 0 {
		t.Fatalf("want no unused-taint findings, got %d", n)
	}
	if got := rep.Nodes[0].Taints[0].TolerantPods; got != 1 {
		t.Errorf("tolerantPods = %d, want 1", got)
	}
	if got := rep.Nodes[0].Taints[0].TolerantWorkloads; got != 1 {
		t.Errorf("tolerantWorkloads = %d, want 1", got)
	}
}

func TestWrongValueDoesNotTolerate(t *testing.T) {
	nodes := []corev1.Node{node("gpu-1", taint("dedicated", "gpu", corev1.TaintEffectNoSchedule))}
	pods := []corev1.Pod{pod("trainer", corev1.Toleration{
		Key: "dedicated", Operator: corev1.TolerationOpEqual, Value: "fpga", Effect: corev1.TaintEffectNoSchedule,
	})}

	rep := analyze(t, nodes, pods, Options{})

	if n := rep.Count(RuleUnusedTaint); n != 1 {
		t.Fatalf("want 1 unused-taint finding, got %d", n)
	}
}

func TestIgnoreTaintSuppressesUnusedTaint(t *testing.T) {
	nodes := []corev1.Node{node("gpu-1", taint("dedicated", "gpu", corev1.TaintEffectNoSchedule))}

	for _, selector := range []string{"dedicated", "dedicated=gpu", "dedicated:NoSchedule", "dedicated=gpu:NoSchedule"} {
		rep := analyze(t, nodes, nil, Options{IgnoreTaints: []string{selector}})
		if n := rep.Count(RuleUnusedTaint); n != 0 {
			t.Errorf("selector %q: want 0 unused-taint findings, got %d", selector, n)
		}
		if !rep.Nodes[0].Taints[0].Ignored {
			t.Errorf("selector %q: taint not marked ignored", selector)
		}
	}

	rep := analyze(t, nodes, nil, Options{IgnoreTaints: []string{"dedicated=fpga"}})
	if n := rep.Count(RuleUnusedTaint); n != 1 {
		t.Errorf("non-matching selector: want 1 finding, got %d", n)
	}
}

func TestOrphanTolerationNamesPodAndKey(t *testing.T) {
	nodes := []corev1.Node{node("worker-1", taint("dedicated", "gpu", corev1.TaintEffectNoSchedule))}
	pods := []corev1.Pod{pod("legacy", corev1.Toleration{
		Key: "spot", Operator: corev1.TolerationOpExists, Effect: corev1.TaintEffectNoSchedule,
	})}

	rep := analyze(t, nodes, pods, Options{})

	got := findingsFor(t, rep, RuleOrphanToleration)
	if len(got) != 1 {
		t.Fatalf("want 1 orphan-toleration finding, got %d", len(got))
	}
	if got[0].Pod != "legacy" || got[0].TolerationKey != "spot" {
		t.Errorf("finding = pod %q key %q, want legacy/spot", got[0].Pod, got[0].TolerationKey)
	}
}

func TestTolerationForExistingTaintKeyIsNotOrphan(t *testing.T) {
	nodes := []corev1.Node{node("worker-1", taint("spot", "true", corev1.TaintEffectNoSchedule))}
	// Value mismatch, so it does not tolerate the taint — but the key exists on
	// a node, which is all orphan-toleration asks about.
	pods := []corev1.Pod{pod("api", corev1.Toleration{
		Key: "spot", Operator: corev1.TolerationOpEqual, Value: "false", Effect: corev1.TaintEffectNoSchedule,
	})}

	rep := analyze(t, nodes, pods, Options{})

	if n := rep.Count(RuleOrphanToleration); n != 0 {
		t.Fatalf("want 0 orphan-toleration findings, got %d", n)
	}
}

func TestBlanketTolerationFiresExactlyOncePerPod(t *testing.T) {
	nodes := []corev1.Node{node("worker-1")}
	pods := []corev1.Pod{pod("agent",
		corev1.Toleration{Operator: corev1.TolerationOpExists},
		corev1.Toleration{Operator: corev1.TolerationOpExists, Effect: corev1.TaintEffectNoExecute},
	)}

	rep := analyze(t, nodes, pods, Options{})

	got := findingsFor(t, rep, RuleBlanketToleration)
	if len(got) != 1 {
		t.Fatalf("want exactly 1 blanket-toleration finding, got %d", len(got))
	}
	if got[0].Pod != "agent" || got[0].Severity != "high" {
		t.Errorf("finding = pod %q severity %q, want agent/high", got[0].Pod, got[0].Severity)
	}
	// The blanket toleration must not also be reported as noexecute-forever:
	// one pod, one actionable line.
	if n := rep.Count(RuleNoExecuteForever); n != 0 {
		t.Errorf("want 0 noexecute-forever findings for a blanket toleration, got %d", n)
	}
}

func TestNoExecuteForeverOnlyWithoutTolerationSeconds(t *testing.T) {
	nodes := []corev1.Node{node("worker-1", taint("dedicated", "gpu", corev1.TaintEffectNoExecute))}

	forever := []corev1.Pod{pod("sticky", corev1.Toleration{
		Key: "dedicated", Operator: corev1.TolerationOpEqual, Value: "gpu", Effect: corev1.TaintEffectNoExecute,
	})}
	rep := analyze(t, nodes, forever, Options{})
	got := findingsFor(t, rep, RuleNoExecuteForever)
	if len(got) != 1 {
		t.Fatalf("want 1 noexecute-forever finding, got %d", len(got))
	}
	if got[0].Pod != "sticky" || got[0].TolerationKey != "dedicated" {
		t.Errorf("finding = pod %q key %q, want sticky/dedicated", got[0].Pod, got[0].TolerationKey)
	}

	bounded := []corev1.Pod{pod("sticky", corev1.Toleration{
		Key: "dedicated", Operator: corev1.TolerationOpEqual, Value: "gpu",
		Effect: corev1.TaintEffectNoExecute, TolerationSeconds: seconds(300),
	})}
	rep = analyze(t, nodes, bounded, Options{})
	if n := rep.Count(RuleNoExecuteForever); n != 0 {
		t.Fatalf("tolerationSeconds set: want 0 findings, got %d", n)
	}
}

func TestEmptyEffectTolerationCoversRealNoExecuteTaint(t *testing.T) {
	nodes := []corev1.Node{node("worker-1", taint("dedicated", "gpu", corev1.TaintEffectNoExecute))}
	pods := []corev1.Pod{pod("sticky", corev1.Toleration{
		Key: "dedicated", Operator: corev1.TolerationOpExists,
	})}

	rep := analyze(t, nodes, pods, Options{})

	if n := rep.Count(RuleNoExecuteForever); n != 1 {
		t.Fatalf("want 1 noexecute-forever finding, got %d", n)
	}
}

func TestEmptyEffectTolerationWithNoNoExecuteTaintIsQuiet(t *testing.T) {
	nodes := []corev1.Node{node("worker-1", taint("dedicated", "gpu", corev1.TaintEffectNoSchedule))}
	pods := []corev1.Pod{pod("batch", corev1.Toleration{
		Key: "dedicated", Operator: corev1.TolerationOpExists,
	})}

	rep := analyze(t, nodes, pods, Options{})

	if n := rep.Count(RuleNoExecuteForever); n != 0 {
		t.Fatalf("want 0 noexecute-forever findings, got %d", n)
	}
}

func TestBuiltinKeysAreSkippedUnlessAsked(t *testing.T) {
	nodes := []corev1.Node{node("sick-1", taint("node.kubernetes.io/not-ready", "", corev1.TaintEffectNoExecute))}
	pods := []corev1.Pod{pod("api", corev1.Toleration{
		Key: "node.kubernetes.io/unreachable", Operator: corev1.TolerationOpExists, Effect: corev1.TaintEffectNoExecute,
	})}

	rep := analyze(t, nodes, pods, Options{})
	if len(rep.Findings) != 0 {
		t.Fatalf("want no findings for builtin keys by default, got %d: %+v", len(rep.Findings), rep.Findings)
	}
	if !rep.Nodes[0].Taints[0].Builtin {
		t.Error("taint not marked builtin")
	}

	rep = analyze(t, nodes, pods, Options{IncludeBuiltin: true})
	if rep.Count(RuleUnusedTaint) != 1 {
		t.Errorf("--include-builtin: want 1 unused-taint finding, got %d", rep.Count(RuleUnusedTaint))
	}
	if rep.Count(RuleOrphanToleration) != 1 {
		t.Errorf("--include-builtin: want 1 orphan-toleration finding, got %d", rep.Count(RuleOrphanToleration))
	}
	if rep.Count(RuleNoExecuteForever) != 1 {
		t.Errorf("--include-builtin: want 1 noexecute-forever finding, got %d", rep.Count(RuleNoExecuteForever))
	}
}

func TestTolerantWorkloadsCollapsesReplicas(t *testing.T) {
	nodes := []corev1.Node{node("worker-1", taint("spot", "true", corev1.TaintEffectNoSchedule))}
	tol := corev1.Toleration{Key: "spot", Operator: corev1.TolerationOpExists}
	pods := []corev1.Pod{
		owned(pod("api-7d9f-aaa", tol), "ReplicaSet", "api-7d9f"),
		owned(pod("api-7d9f-bbb", tol), "ReplicaSet", "api-7d9f"),
		owned(pod("logs-xyz", tol), "DaemonSet", "logs"),
	}

	rep := analyze(t, nodes, pods, Options{})

	tv := rep.Nodes[0].Taints[0]
	if tv.TolerantPods != 3 {
		t.Errorf("tolerantPods = %d, want 3", tv.TolerantPods)
	}
	if tv.TolerantWorkloads != 2 {
		t.Errorf("tolerantWorkloads = %d, want 2", tv.TolerantWorkloads)
	}
}

func TestOrphanTolerationReportedOncePerKeyPerPod(t *testing.T) {
	nodes := []corev1.Node{node("worker-1")}
	pods := []corev1.Pod{pod("legacy",
		corev1.Toleration{Key: "spot", Operator: corev1.TolerationOpExists, Effect: corev1.TaintEffectNoSchedule},
		corev1.Toleration{Key: "spot", Operator: corev1.TolerationOpEqual, Value: "true", Effect: corev1.TaintEffectNoSchedule},
	)}

	rep := analyze(t, nodes, pods, Options{})

	if n := rep.Count(RuleOrphanToleration); n != 1 {
		t.Fatalf("want 1 orphan-toleration finding, got %d", n)
	}
}

func TestFiredAndParseRules(t *testing.T) {
	nodes := []corev1.Node{node("gpu-1", taint("dedicated", "gpu", corev1.TaintEffectNoSchedule))}
	rep := analyze(t, nodes, nil, Options{})

	rules, err := ParseRules([]string{"unused-taint,blanket-toleration"})
	if err != nil {
		t.Fatalf("ParseRules: %v", err)
	}
	if len(rules) != 2 {
		t.Fatalf("want 2 rules, got %d", len(rules))
	}
	if !rep.Fired(rules) {
		t.Error("want Fired true for unused-taint")
	}

	only, err := ParseRules([]string{"blanket-toleration"})
	if err != nil {
		t.Fatalf("ParseRules: %v", err)
	}
	if rep.Fired(only) {
		t.Error("want Fired false for blanket-toleration")
	}

	all, err := ParseRules([]string{"all"})
	if err != nil {
		t.Fatalf("ParseRules(all): %v", err)
	}
	if len(all) != len(AllRules()) {
		t.Errorf("ParseRules(all) = %d rules, want %d", len(all), len(AllRules()))
	}
	if _, err := ParseRules([]string{"unused-taints"}); err == nil {
		t.Error("want an error for a misspelled rule name")
	}
}

func TestBadTaintSelectorIsAnError(t *testing.T) {
	for _, bad := range []string{"", "=gpu", "dedicated=gpu:Nope", ":NoSchedule"} {
		if _, err := Analyze(nil, nil, Options{IgnoreTaints: []string{bad}}); err == nil {
			t.Errorf("selector %q: want an error, got none", bad)
		}
	}
}

func TestToleratesMatrix(t *testing.T) {
	gpu := taint("dedicated", "gpu", corev1.TaintEffectNoSchedule)
	cases := []struct {
		name string
		tol  corev1.Toleration
		want bool
	}{
		{"exact equal", corev1.Toleration{Key: "dedicated", Operator: corev1.TolerationOpEqual, Value: "gpu", Effect: corev1.TaintEffectNoSchedule}, true},
		{"operator defaults to equal", corev1.Toleration{Key: "dedicated", Value: "gpu"}, true},
		{"exists ignores value", corev1.Toleration{Key: "dedicated", Operator: corev1.TolerationOpExists, Value: "fpga"}, true},
		{"empty key with exists matches all", corev1.Toleration{Operator: corev1.TolerationOpExists}, true},
		{"wrong effect", corev1.Toleration{Key: "dedicated", Operator: corev1.TolerationOpExists, Effect: corev1.TaintEffectNoExecute}, false},
		{"wrong key", corev1.Toleration{Key: "spot", Operator: corev1.TolerationOpExists}, false},
		{"wrong value", corev1.Toleration{Key: "dedicated", Operator: corev1.TolerationOpEqual, Value: "fpga"}, false},
		{"unknown operator", corev1.Toleration{Key: "dedicated", Operator: corev1.TolerationOperator("Matches")}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Tolerates(tc.tol, gpu); got != tc.want {
				t.Errorf("Tolerates = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestRenderTableListsTaintsAndFindings(t *testing.T) {
	nodes := []corev1.Node{node("gpu-1", taint("dedicated", "gpu", corev1.TaintEffectNoSchedule))}
	pods := []corev1.Pod{pod("agent", corev1.Toleration{Operator: corev1.TolerationOpExists})}
	rep := analyze(t, nodes, pods, Options{})

	var buf bytes.Buffer
	if err := RenderTable(&buf, rep); err != nil {
		t.Fatalf("RenderTable: %v", err)
	}
	out := buf.String()
	for _, want := range []string{"dedicated=gpu:NoSchedule", "blanket-toleration", "1 nodes (1 tainted)", "default/agent", "catch-all"} {
		if !strings.Contains(out, want) {
			t.Errorf("table output missing %q:\n%s", want, out)
		}
	}
}

func TestCatchAllTolerationDoesNotHideAnUnusedTaint(t *testing.T) {
	// One node-exporter style DaemonSet with an empty-key Exists toleration
	// matches every taint in the cluster. If that counted as usage, the
	// unused-taint rule could never fire anywhere.
	nodes := []corev1.Node{node("gpu-1", taint("dedicated", "gpu", corev1.TaintEffectNoSchedule))}
	pods := []corev1.Pod{owned(pod("node-agent-xyz", corev1.Toleration{Operator: corev1.TolerationOpExists}), "DaemonSet", "node-agent")}

	rep := analyze(t, nodes, pods, Options{})

	got := findingsFor(t, rep, RuleUnusedTaint)
	if len(got) != 1 {
		t.Fatalf("want 1 unused-taint finding, got %d", len(got))
	}
	if !strings.Contains(got[0].Message, "catch-all") {
		t.Errorf("message should name the catch-all pods: %q", got[0].Message)
	}
	tv := rep.Nodes[0].Taints[0]
	if tv.TolerantPods != 0 || tv.TolerantWorkloads != 0 {
		t.Errorf("tolerant = %d pods / %d workloads, want 0/0", tv.TolerantPods, tv.TolerantWorkloads)
	}
	if tv.BlanketPods != 1 || tv.BlanketWorkloads != 1 {
		t.Errorf("blanket = %d pods / %d workloads, want 1/1", tv.BlanketPods, tv.BlanketWorkloads)
	}
}

func TestPodTolerationKind(t *testing.T) {
	gpu := taint("dedicated", "gpu", corev1.TaintEffectNoSchedule)
	cases := []struct {
		name                      string
		pod                       corev1.Pod
		wantSpecific, wantBlanket bool
	}{
		{"named key", pod("a", corev1.Toleration{Key: "dedicated", Operator: corev1.TolerationOpExists}), true, false},
		{"catch-all only", pod("b", corev1.Toleration{Operator: corev1.TolerationOpExists}), false, true},
		{"both", pod("c",
			corev1.Toleration{Operator: corev1.TolerationOpExists},
			corev1.Toleration{Key: "dedicated", Operator: corev1.TolerationOpExists},
		), true, true},
		{"neither", pod("d", corev1.Toleration{Key: "spot", Operator: corev1.TolerationOpExists}), false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := tc.pod
			specific, blanket := PodTolerationKind(&p, gpu)
			if specific != tc.wantSpecific || blanket != tc.wantBlanket {
				t.Errorf("got specific=%v blanket=%v, want %v/%v", specific, blanket, tc.wantSpecific, tc.wantBlanket)
			}
		})
	}
}

func TestRenderSuggestions(t *testing.T) {
	nodes := []corev1.Node{node("gpu-1", taint("dedicated", "gpu", corev1.TaintEffectNoSchedule))}
	rep := analyze(t, nodes, []corev1.Pod{pod("web")}, Options{})

	var buf bytes.Buffer
	RenderSuggestions(&buf, rep)
	if got := buf.String(); !strings.Contains(got, "kubectl taint nodes gpu-1 dedicated=gpu:NoSchedule-") {
		t.Errorf("suggestions missing the removal command:\n%s", got)
	}

	buf.Reset()
	clean := analyze(t, []corev1.Node{node("worker-1")}, nil, Options{})
	RenderSuggestions(&buf, clean)
	if buf.Len() != 0 {
		t.Errorf("want no suggestions for a clean report, got %q", buf.String())
	}
}

func TestRenderJSONRoundTrips(t *testing.T) {
	nodes := []corev1.Node{node("gpu-1", taint("dedicated", "gpu", corev1.TaintEffectNoSchedule))}
	rep := analyze(t, nodes, nil, Options{})

	var buf bytes.Buffer
	if err := RenderJSON(&buf, rep); err != nil {
		t.Fatalf("RenderJSON: %v", err)
	}
	if !strings.Contains(buf.String(), `"rule": "unused-taint"`) {
		t.Errorf("json output missing the rule field:\n%s", buf.String())
	}
}

func TestCleanClusterHasNoFindings(t *testing.T) {
	nodes := []corev1.Node{node("worker-1", taint("spot", "true", corev1.TaintEffectNoSchedule))}
	pods := []corev1.Pod{pod("api", corev1.Toleration{
		Key: "spot", Operator: corev1.TolerationOpEqual, Value: "true", Effect: corev1.TaintEffectNoSchedule,
	})}

	rep := analyze(t, nodes, pods, Options{})

	if len(rep.Findings) != 0 {
		t.Fatalf("want a clean report, got %+v", rep.Findings)
	}
	var buf bytes.Buffer
	if err := RenderTable(&buf, rep); err != nil {
		t.Fatalf("RenderTable: %v", err)
	}
	if !strings.Contains(buf.String(), "clean") {
		t.Errorf("table output should say clean:\n%s", buf.String())
	}
}

func TestWorkloadOf(t *testing.T) {
	cases := []struct {
		name string
		pod  corev1.Pod
		want string
	}{
		{"replicaset folds to deployment", owned(pod("api-7d9f-aaa"), "ReplicaSet", "api-7d9f"), "Deployment/api"},
		{"daemonset kept as is", owned(pod("logs-xyz"), "DaemonSet", "logs"), "DaemonSet/logs"},
		{"bare pod", pod("debug"), "Pod/debug"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := tc.pod
			if got := WorkloadOf(&p); got != tc.want {
				t.Errorf("WorkloadOf = %q, want %q", got, tc.want)
			}
		})
	}
}

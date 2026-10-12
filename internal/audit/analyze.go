package audit

import (
	"fmt"
	"sort"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
)

// Analyze matches node taints against pod tolerations in both directions and
// returns the per-node picture plus every finding.
func Analyze(nodes []corev1.Node, pods []corev1.Pod, opts Options) (Report, error) {
	selectors, err := parseSelectors(opts.IgnoreTaints)
	if err != nil {
		return Report{}, err
	}

	rep := Report{
		NodesTotal: len(nodes),
		PodsTotal:  len(pods),
		Summary:    map[string]int{},
	}

	// Every taint key present anywhere in the cluster, used by the
	// orphan-toleration rule. Ignored taints still count as present: an
	// --ignore-taint flag suppresses unused-taint noise, it does not pretend the
	// taint is gone.
	taintKeys := map[string]bool{}
	// NoExecute taints that actually exist, so an effect-less toleration can be
	// resolved against reality rather than guessed at.
	var noExecuteTaints []corev1.Taint
	for i := range nodes {
		for _, t := range nodes[i].Spec.Taints {
			taintKeys[t.Key] = true
			if t.Effect == corev1.TaintEffectNoExecute {
				noExecuteTaints = append(noExecuteTaints, t)
			}
		}
	}

	strandedCPU := resource.NewQuantity(0, resource.DecimalSI)
	strandedMem := resource.NewQuantity(0, resource.BinarySI)

	for i := range nodes {
		node := &nodes[i]
		cpu := node.Status.Allocatable[corev1.ResourceCPU]
		mem := node.Status.Allocatable[corev1.ResourceMemory]
		view := NodeView{
			Name:              node.Name,
			AllocatableCPU:    cpu.String(),
			AllocatableMemory: mem.String(),
		}
		if len(node.Spec.Taints) > 0 {
			rep.TaintedNodes++
		}
		strandedHere := false

		for _, taint := range node.Spec.Taints {
			tv := TaintView{
				Key:     taint.Key,
				Value:   taint.Value,
				Effect:  string(taint.Effect),
				Taint:   TaintString(taint),
				Builtin: IsBuiltinKey(taint.Key),
			}
			for _, sel := range selectors {
				if sel.matches(taint) {
					tv.Ignored = true
					break
				}
			}

			workloads := map[string]bool{}
			blanketWorkloads := map[string]bool{}
			for j := range pods {
				specific, blanket := PodTolerationKind(&pods[j], taint)
				key := pods[j].Namespace + "/" + WorkloadOf(&pods[j])
				switch {
				case specific:
					tv.TolerantPods++
					workloads[key] = true
				case blanket:
					tv.BlanketPods++
					blanketWorkloads[key] = true
				}
			}
			tv.TolerantWorkloads = len(workloads)
			tv.BlanketWorkloads = len(blanketWorkloads)
			view.Taints = append(view.Taints, tv)

			skip := tv.Ignored || (tv.Builtin && !opts.IncludeBuiltin)
			if skip || tv.TolerantPods > 0 {
				continue
			}
			strandedHere = true
			msg := fmt.Sprintf("no pod in the cluster tolerates %s; %s CPU and %s memory on %s take no workload",
				tv.Taint, view.AllocatableCPU, view.AllocatableMemory, node.Name)
			if tv.BlanketPods > 0 {
				verb := "pods land"
				if tv.BlanketPods == 1 {
					verb = "pod lands"
				}
				msg += fmt.Sprintf(" (%d catch-all %s there, but nothing asks for this taint)", tv.BlanketPods, verb)
			}
			rep.add(Finding{
				Rule:              RuleUnusedTaint,
				Node:              node.Name,
				Taint:             tv.Taint,
				Effect:            tv.Effect,
				AllocatableCPU:    view.AllocatableCPU,
				AllocatableMemory: view.AllocatableMemory,
				Message:           msg,
			})
		}

		if strandedHere {
			strandedCPU.Add(cpu)
			strandedMem.Add(mem)
		}
		rep.Nodes = append(rep.Nodes, view)
	}
	rep.StrandedCPU = strandedCPU.String()
	rep.StrandedMemory = strandedMem.String()

	for i := range pods {
		analyzePod(&rep, &pods[i], taintKeys, noExecuteTaints, opts)
	}

	rep.sort()
	return rep, nil
}

func analyzePod(rep *Report, pod *corev1.Pod, taintKeys map[string]bool, noExecuteTaints []corev1.Taint, opts Options) {
	workload := WorkloadOf(pod)
	blanketReported := false
	orphanSeen := map[string]bool{}
	foreverSeen := map[string]bool{}

	for _, tol := range pod.Spec.Tolerations {
		// A toleration with an empty key and operator Exists swallows every
		// taint there is, including not-ready and unreachable, so the pod stays
		// scheduled on a node the control plane has already given up on. Once
		// per pod is enough; the rest of the rules have nothing to add.
		if tol.Key == "" && tol.Operator == corev1.TolerationOpExists {
			if !blanketReported {
				blanketReported = true
				rep.add(Finding{
					Rule:      RuleBlanketToleration,
					Namespace: pod.Namespace,
					Pod:       pod.Name,
					Workload:  workload,
					Effect:    string(tol.Effect),
					Message: fmt.Sprintf("%s tolerates every taint (empty key, operator Exists), including node.kubernetes.io/not-ready and unreachable",
						pod.Name),
				})
			}
			continue
		}
		if tol.Key == "" {
			continue
		}
		if IsBuiltinKey(tol.Key) && !opts.IncludeBuiltin {
			continue
		}

		if !taintKeys[tol.Key] && !orphanSeen[tol.Key] {
			orphanSeen[tol.Key] = true
			rep.add(Finding{
				Rule:          RuleOrphanToleration,
				Namespace:     pod.Namespace,
				Pod:           pod.Name,
				Workload:      workload,
				TolerationKey: tol.Key,
				Effect:        string(tol.Effect),
				Message: fmt.Sprintf("toleration for %q matches no taint on any node: scheduling config that reads as intent and does nothing",
					tol.Key),
			})
		}

		if tol.TolerationSeconds != nil || foreverSeen[tol.Key] {
			continue
		}
		if !tolerationCoversNoExecute(tol, noExecuteTaints) {
			continue
		}
		foreverSeen[tol.Key] = true
		rep.add(Finding{
			Rule:          RuleNoExecuteForever,
			Namespace:     pod.Namespace,
			Pod:           pod.Name,
			Workload:      workload,
			TolerationKey: tol.Key,
			Effect:        string(corev1.TaintEffectNoExecute),
			Message: fmt.Sprintf("NoExecute toleration for %q has no tolerationSeconds: on node failure this pod is never evicted",
				tol.Key),
		})
	}
}

// tolerationCoversNoExecute reports whether a toleration lets its pod survive a
// NoExecute taint: either the effect says so outright, or the effect is empty
// (which matches every effect) and a NoExecute taint with that key really exists.
func tolerationCoversNoExecute(tol corev1.Toleration, noExecuteTaints []corev1.Taint) bool {
	if tol.Effect == corev1.TaintEffectNoExecute {
		return true
	}
	if tol.Effect != "" {
		return false
	}
	for _, t := range noExecuteTaints {
		if Tolerates(tol, t) {
			return true
		}
	}
	return false
}

func (r *Report) add(f Finding) {
	f.Severity = severities[f.Rule]
	r.Findings = append(r.Findings, f)
	r.Summary[string(f.Rule)]++
}

func (r *Report) sort() {
	order := map[Rule]int{}
	for i, rule := range AllRules() {
		order[rule] = i
	}
	sort.SliceStable(r.Findings, func(i, j int) bool {
		a, b := r.Findings[i], r.Findings[j]
		if order[a.Rule] != order[b.Rule] {
			return order[a.Rule] < order[b.Rule]
		}
		if a.Node != b.Node {
			return a.Node < b.Node
		}
		if a.Namespace != b.Namespace {
			return a.Namespace < b.Namespace
		}
		if a.Pod != b.Pod {
			return a.Pod < b.Pod
		}
		if a.Taint != b.Taint {
			return a.Taint < b.Taint
		}
		return a.TolerationKey < b.TolerationKey
	})
}

// ParseRules turns a --fail-on argument into rules, rejecting unknown names so
// a typo fails loudly instead of quietly never firing.
func ParseRules(args []string) ([]Rule, error) {
	var out []Rule
	seen := map[Rule]bool{}
	for _, arg := range args {
		for _, part := range splitList(arg) {
			if part == "all" {
				for _, r := range AllRules() {
					if !seen[r] {
						seen[r] = true
						out = append(out, r)
					}
				}
				continue
			}
			if !ValidRule(part) {
				return nil, fmt.Errorf("unknown rule %q (known: blanket-toleration, noexecute-forever, unused-taint, orphan-toleration, all)", part)
			}
			r := Rule(part)
			if !seen[r] {
				seen[r] = true
				out = append(out, r)
			}
		}
	}
	return out, nil
}

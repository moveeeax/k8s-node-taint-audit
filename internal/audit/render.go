package audit

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
)

func splitList(arg string) []string {
	var out []string
	for _, part := range strings.Split(arg, ",") {
		if p := strings.TrimSpace(part); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// RenderSuggestions prints the kubectl commands that would remove every taint
// flagged as unused. Nothing is executed: a taint can be load-bearing for a
// workload that is scaled to zero right now, so a human reads the list first.
func RenderSuggestions(w io.Writer, rep Report) {
	var lines []string
	for _, f := range rep.Findings {
		if f.Rule != RuleUnusedTaint {
			continue
		}
		lines = append(lines, fmt.Sprintf("kubectl taint nodes %s %s-", f.Node, f.Taint))
	}
	if len(lines) == 0 {
		return
	}
	fmt.Fprintf(w, "\n# remove the unused taints (review before running)\n")
	for _, l := range lines {
		fmt.Fprintln(w, l)
	}
}

// RenderJSON writes the report as indented JSON.
func RenderJSON(w io.Writer, rep Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(rep)
}

// RenderTable writes the human-readable report: the taint picture per node
// first, then the findings, then one summary line.
func RenderTable(w io.Writer, rep Report) error {
	tw := tabwriter.NewWriter(w, 0, 8, 2, ' ', 0)

	fmt.Fprintf(tw, "NODE\tTAINT\tTOLERATED BY\tALLOCATABLE\n")
	printed := 0
	for _, n := range rep.Nodes {
		for _, t := range n.Taints {
			note := ""
			switch {
			case t.Ignored:
				note = " (ignored)"
			case t.Builtin:
				note = " (builtin)"
			}
			if t.BlanketPods > 0 {
				note += fmt.Sprintf(" +%d catch-all", t.BlanketPods)
			}
			fmt.Fprintf(tw, "%s\t%s\t%d workloads / %d pods%s\t%s cpu, %s mem\n",
				n.Name, t.Taint, t.TolerantWorkloads, t.TolerantPods, note,
				n.AllocatableCPU, n.AllocatableMemory)
			printed++
		}
	}
	if printed == 0 {
		fmt.Fprintf(tw, "-\t(no taints on any node)\t-\t-\n")
	}
	if err := tw.Flush(); err != nil {
		return err
	}

	fmt.Fprintln(w)
	ftw := tabwriter.NewWriter(w, 0, 8, 2, ' ', 0)
	fmt.Fprintf(ftw, "RULE\tSEVERITY\tOBJECT\tDETAIL\n")
	for _, f := range rep.Findings {
		detail := f.Taint
		if detail == "" {
			detail = f.TolerationKey
		}
		if detail == "" {
			detail = "-"
		}
		fmt.Fprintf(ftw, "%s\t%s\t%s\t%s\n", f.Rule, f.Severity, f.Object(), detail)
	}
	if len(rep.Findings) == 0 {
		fmt.Fprintf(ftw, "-\t-\t-\t(no findings)\n")
	}
	if err := ftw.Flush(); err != nil {
		return err
	}

	fmt.Fprintln(w)
	for _, f := range rep.Findings {
		fmt.Fprintf(w, "%s  %s: %s\n", f.Rule, f.Object(), f.Message)
	}
	if len(rep.Findings) > 0 {
		fmt.Fprintln(w)
	}

	var parts []string
	for _, rule := range AllRules() {
		if n := rep.Count(rule); n > 0 {
			parts = append(parts, fmt.Sprintf("%s=%d", rule, n))
		}
	}
	summary := "clean"
	if len(parts) > 0 {
		summary = strings.Join(parts, " ")
	}
	fmt.Fprintf(w, "%d nodes (%d tainted), %d pods, %d findings: %s\n",
		rep.NodesTotal, rep.TaintedNodes, rep.PodsTotal, len(rep.Findings), summary)
	if rep.Count(RuleUnusedTaint) > 0 {
		fmt.Fprintf(w, "stranded allocatable behind unused taints: %s cpu, %s mem\n",
			rep.StrandedCPU, rep.StrandedMemory)
	}
	return nil
}

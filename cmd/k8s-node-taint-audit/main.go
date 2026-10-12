// Command k8s-node-taint-audit matches node taints against the tolerations
// workloads actually declare, in both directions, and reports the mismatches.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"

	"github.com/moveeeax/k8s-node-taint-audit/internal/audit"
	"github.com/moveeeax/k8s-node-taint-audit/internal/fixture"
	"github.com/moveeeax/k8s-node-taint-audit/internal/kube"
)

// version is overridden at build time with -ldflags "-X main.version=...".
var version = "0.1.0"

type stringList []string

func (s *stringList) String() string     { return strings.Join(*s, ",") }
func (s *stringList) Set(v string) error { *s = append(*s, v); return nil }

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		if ec, ok := err.(exitCode); ok {
			os.Exit(int(ec))
		}
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(2)
	}
}

// exitCode carries a wanted exit status without an error message, which is how
// --fail-on reports "findings fired" to CI after the report has been printed.
type exitCode int

func (e exitCode) Error() string { return fmt.Sprintf("exit status %d", int(e)) }

func run(args []string, stdout, stderr *os.File) error {
	fs := flag.NewFlagSet("k8s-node-taint-audit", flag.ContinueOnError)
	fs.SetOutput(stderr)

	var ignore, failOn stringList
	kubeconfig := fs.String("kubeconfig", "", "path to the kubeconfig file (default: $KUBECONFIG, then ~/.kube/config)")
	kubeContext := fs.String("context", "", "kubeconfig context to use (default: current context)")
	fromFile := fs.String("from-file", "", "audit a captured snapshot of nodes and pods instead of a live cluster")
	format := fs.String("format", "table", "output format: table or json")
	includeBuiltin := fs.Bool("include-builtin", false, "also audit node.kubernetes.io/ taint keys the control plane manages itself")
	suggest := fs.Bool("suggest", false, "print the kubectl taint commands that would remove each unused taint")
	timeout := fs.Duration("timeout", 30*time.Second, "timeout for the Kubernetes API calls")
	showVersion := fs.Bool("version", false, "print the version and exit")
	fs.Var(&ignore, "ignore-taint", "taint to treat as known-good: key, key=value, key:Effect or key=value:Effect (repeatable)")
	fs.Var(&failOn, "fail-on", "exit 1 if any of these rules fired: unused-taint, orphan-toleration, blanket-toleration, noexecute-forever, all (repeatable)")

	fs.Usage = func() {
		fmt.Fprintf(stderr, "k8s-node-taint-audit — audit node taints against real workload tolerations\n\nUsage:\n  k8s-node-taint-audit [flags]\n\nFlags:\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return exitCode(2)
	}
	if *showVersion {
		fmt.Fprintln(stdout, version)
		return nil
	}
	if *format != "table" && *format != "json" {
		return fmt.Errorf("unknown --format %q (want table or json)", *format)
	}
	rules, err := audit.ParseRules(failOn)
	if err != nil {
		return err
	}

	var nodes []corev1.Node
	var pods []corev1.Pod
	if *fromFile != "" {
		nodes, pods, err = fixture.Load(*fromFile)
	} else {
		client, cerr := kube.Client(*kubeconfig, *kubeContext)
		if cerr != nil {
			return cerr
		}
		ctx, cancel := context.WithTimeout(context.Background(), *timeout)
		defer cancel()
		nodes, pods, err = kube.Fetch(ctx, client)
	}
	if err != nil {
		return err
	}

	rep, err := audit.Analyze(nodes, pods, audit.Options{
		IgnoreTaints:   ignore,
		IncludeBuiltin: *includeBuiltin,
	})
	if err != nil {
		return err
	}

	if *format == "json" {
		if err := audit.RenderJSON(stdout, rep); err != nil {
			return err
		}
	} else {
		if err := audit.RenderTable(stdout, rep); err != nil {
			return err
		}
		// Suggestions are plain shell lines, so they would break a JSON
		// consumer; the JSON report already carries node and taint per finding.
		if *suggest {
			audit.RenderSuggestions(stdout, rep)
		}
	}

	if len(rules) > 0 && rep.Fired(rules) {
		return exitCode(1)
	}
	return nil
}

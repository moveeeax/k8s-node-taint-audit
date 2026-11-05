# k8s-node-taint-audit

[![ci](https://github.com/moveeeax/k8s-node-taint-audit/actions/workflows/ci.yml/badge.svg)](https://github.com/moveeeax/k8s-node-taint-audit/actions/workflows/ci.yml)
[![go](https://img.shields.io/badge/go-1.26%2B-00ADD8)](https://go.dev/dl/)
[![license](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

Audit Kubernetes node taints against the tolerations your workloads actually declare — in both
directions. Taints nothing tolerates are stranded capacity you still pay for. Tolerations whose key
is on no node are dead scheduling config that reads as intent. `kubectl describe node` prints taints
one node at a time and never tells you whether anything in the cluster tolerates them.

## What it reports

| rule | fires when | why it matters |
| --- | --- | --- |
| `unused-taint` | a node taint no pod tolerates by name | the node is in the cluster, in the bill, and takes no pods |
| `orphan-toleration` | a toleration whose key is on no node | careful-looking config that does nothing; the pod lands wherever |
| `blanket-toleration` | a toleration with an empty key and `operator: Exists` | tolerates `not-ready` and `unreachable` too, so the pod sits on a dead node |
| `noexecute-forever` | a `NoExecute` toleration with no `tolerationSeconds` | on node failure the pod is never evicted |

Control-plane taint keys (`node.kubernetes.io/*`, `node.cloudprovider.kubernetes.io/*`) are skipped
by default: they are transient by design and the `DefaultTolerationSeconds` admission plugin injects
tolerations for them into nearly every pod. Pass `--include-builtin` to audit them anyway.

## Install

```
go install github.com/moveeeax/k8s-node-taint-audit/cmd/k8s-node-taint-audit@latest
```

Or build from a checkout:

```
go build -o k8s-node-taint-audit ./cmd/k8s-node-taint-audit
```

## Usage

Against the current kubeconfig context:

```
k8s-node-taint-audit
```

Against a captured snapshot, which is how the bundled example works and how CI tests the tool with
no cluster at all:

```
$ k8s-node-taint-audit --from-file examples/cluster.yaml
NODE          TAINT                         TOLERATED BY                       ALLOCATABLE
ip-10-0-1-11  dedicated=gpu:NoSchedule      0 workloads / 0 pods +1 catch-all  16 cpu, 64Gi mem
ip-10-0-2-24  spot=true:NoSchedule          1 workloads / 2 pods +1 catch-all  8 cpu, 32Gi mem
ip-10-0-2-24  workload=streaming:NoExecute  1 workloads / 1 pods +1 catch-all  8 cpu, 32Gi mem

RULE                SEVERITY  OBJECT                              DETAIL
blanket-toleration  high      monitoring/node-agent-pqrst         -
noexecute-forever   medium    streaming/streaming-ingest-0        workload
unused-taint        medium    node/ip-10-0-1-11                   dedicated=gpu:NoSchedule
orphan-toleration   low       platform/cache-warmer-55d8b7-klmno  memory-optimized

3 nodes (2 tainted), 5 pods, 4 findings: blanket-toleration=1 noexecute-forever=1 unused-taint=1 orphan-toleration=1
stranded allocatable behind unused taints: 16 cpu, 64Gi mem
```

A snapshot is anything `kubectl` already gives you:

```
kubectl get nodes,pods -A -o yaml > snapshot.yaml
k8s-node-taint-audit --from-file snapshot.yaml
```

JSON for pipelines:

```
k8s-node-taint-audit --format json | jq '.findings[] | select(.rule=="unused-taint")'
```

In CI, with a real GPU pool declared known-good:

```
k8s-node-taint-audit --ignore-taint dedicated=gpu --fail-on unused-taint,blanket-toleration
```

Exit codes: `0` nothing to report (or nothing in `--fail-on` fired), `1` a `--fail-on` rule fired,
`2` the run itself failed.

The removal commands for stranded taints, printed and never executed:

```
$ k8s-node-taint-audit --from-file examples/cluster.yaml --suggest | tail -2
# remove the unused taints (review before running)
kubectl taint nodes ip-10-0-1-11 dedicated=gpu:NoSchedule-
```

### Flags

| flag | meaning |
| --- | --- |
| `--kubeconfig` | kubeconfig path; defaults to `$KUBECONFIG`, then `~/.kube/config`, then in-cluster |
| `--context` | kubeconfig context; defaults to the current one |
| `--from-file` | audit a snapshot of nodes and pods instead of a live cluster |
| `--format` | `table` (default) or `json` |
| `--ignore-taint` | known-good taint: `key`, `key=value`, `key:Effect`, `key=value:Effect`; repeatable |
| `--fail-on` | rules that make the exit code 1; `all` accepted; repeatable |
| `--include-builtin` | also audit `node.kubernetes.io/*` taint keys |
| `--suggest` | print the `kubectl taint ... -` commands for unused taints |
| `--timeout` | timeout for the API calls (default `30s`) |

## How it works

Everything that decides anything lives in `internal/audit`: `Analyze` takes `[]corev1.Node` and
`[]corev1.Pod` and returns findings. It reimplements the scheduler's own matching rules — an empty
effect matches every effect, an empty key with `Exists` matches every key, `Exists` ignores the
value, an unset operator means `Equal` — so the report agrees with what the scheduler would do.
`internal/kube` is a thin adapter around client-go, and `internal/fixture` loads a snapshot off
disk. That split is why `go test ./...` needs no cluster and no credentials.

One decision worth knowing about: a catch-all toleration (empty key, `operator: Exists`) is counted
separately from real tolerations. Most clusters run one node-exporter or CNI DaemonSet with exactly
that toleration, and it matches every taint there is — if it counted as usage, `unused-taint` could
never fire anywhere. Catch-all pods show up as `+N catch-all` in the table and in `blanketPods` in
the JSON, and the `unused-taint` message says how many landed there.

## RBAC

Read-only, cluster-scoped:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: node-taint-audit
rules:
  - apiGroups: [""]
    resources: ["nodes", "pods"]
    verbs: ["get", "list"]
```

## License

MIT

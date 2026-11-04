#!/usr/bin/env bash
# Shared settings for the minikube end-to-end test. Source it: `source hack/minikube/env.sh`
#
# The test cluster gets its OWN kubeconfig file, so ~/.kube/config (and its current context) is never touched,
# and every tool below is pointed at that file explicitly.

export E2E_PROFILE="${E2E_PROFILE:-secobserve-e2e}"
export E2E_DIR="${E2E_DIR:?set E2E_DIR to a scratch directory}"
export KUBECONFIG="$E2E_DIR/kubeconfig"
export MINIKUBE_HOME="${MINIKUBE_HOME:-$HOME/.minikube}"
mkdir -p "$E2E_DIR"

# Abort unless the kubeconfig points to a local minikube API server.
e2e_guard() {
  python3 - "$KUBECONFIG" "$E2E_PROFILE" <<'EOF' || { echo "GUARD: refusing to talk to a non-local cluster" >&2; return 1; }
import sys, re
try:
    import yaml
except ImportError:
    yaml = None
path, profile = sys.argv[1], sys.argv[2]
text = open(path).read()
servers = re.findall(r"server:\s*(\S+)", text)
current = re.search(r"current-context:\s*(\S+)", text)
ok_server = bool(servers) and all(re.match(r"https://(127\.0\.0\.1|localhost|192\.168\.\d+\.\d+)(:\d+)?$", s) for s in servers)
ok_context = bool(current) and current.group(1) == profile
if not (ok_server and ok_context):
    print(f"GUARD: servers={servers} current-context={current.group(1) if current else None}", file=sys.stderr)
    sys.exit(1)
EOF
}

e2e_helm() { e2e_guard && helm --kubeconfig "$KUBECONFIG" --kube-context "$E2E_PROFILE" "$@"; }

"""Tiny kubectl replacement for the e2e test (apply / delete / status / logs), guarded to local clusters only.

usage: KUBECONFIG=... python hack/minikube/k8s.py <command> [...]
  apply FILE...                  server-side apply of all documents in the YAML files
  delete KIND NAMESPACE NAME     e.g. delete Deployment shop-prod nginx
  status                         pods and Trivy reports per namespace
  reports [NAMESPACE]            VulnerabilityReports with image and counts
  logs NAMESPACE LABELSELECTOR [TAIL]
  wait-reports N [TIMEOUT]       wait until at least N VulnerabilityReports exist
  set-image NAMESPACE DEPLOYMENT CONTAINER IMAGE
  annotate NAMESPACE KEY=VALUE   set (or with KEY- remove) an annotation of a namespace
  scale NAMESPACE KIND NAME N    scale a Deployment or StatefulSet
  pods NAMESPACE                 pods with phase, readiness and restarts
  exec NAMESPACE LABELSELECTOR CONTAINER CMD...   run a command in the first matching pod
  restart NAMESPACE DEPLOYMENT   rolling restart (like kubectl rollout restart)
  wait-ready NAMESPACE LABELSELECTOR [TIMEOUT]    wait until all matching pods are ready
  job-status NAMESPACE NAME      succeeded/failed/active of a Job
"""

from __future__ import annotations

import collections
import os
import re
import sys
import time

import yaml
from kubernetes import client, config, dynamic

GROUP, VERSION = "aquasecurity.github.io", "v1alpha1"


def connect() -> client.ApiClient:
    kubeconfig = os.environ["KUBECONFIG"]
    config.load_kube_config(config_file=kubeconfig)
    host = client.Configuration.get_default_copy().host
    if not re.match(r"https://(127\.0\.0\.1|localhost|192\.168\.\d+\.\d+)(:\d+)?$", host):
        sys.exit(f"GUARD: refusing to talk to non-local API server {host}")
    return client.ApiClient()


def cmd_apply(api: client.ApiClient, files: list[str]) -> None:
    dyn = dynamic.DynamicClient(api)
    for path in files:
        for doc in yaml.safe_load_all(open(path)):
            if not doc:
                continue
            resource = dyn.resources.get(api_version=doc["apiVersion"], kind=doc["kind"])
            namespace = doc["metadata"].get("namespace")
            resource.server_side_apply(body=doc, namespace=namespace, field_manager="e2e", force_conflicts=True)
            print(f"applied {doc['kind']} {namespace or ''}/{doc['metadata']['name']}")


def cmd_delete(api: client.ApiClient, kind: str, namespace: str, name: str) -> None:
    dyn = dynamic.DynamicClient(api)
    api_version = {
        "Deployment": "apps/v1",
        "CronJob": "batch/v1",
        "Job": "batch/v1",
        "Namespace": "v1",
        "StatefulSet": "apps/v1",
    }.get(kind, "v1")
    resource = dyn.resources.get(api_version=api_version, kind=kind)
    if kind == "Namespace":
        resource.delete(name=name)
    else:
        resource.delete(name=name, namespace=namespace, body={"propagationPolicy": "Foreground"})
    print(f"deleted {kind} {namespace}/{name}")


def _reports(api: client.ApiClient, plural: str, namespace: str | None = None) -> list[dict]:
    custom = client.CustomObjectsApi(api)
    if namespace:
        return custom.list_namespaced_custom_object(GROUP, VERSION, namespace, plural)["items"]
    return custom.list_cluster_custom_object(GROUP, VERSION, plural)["items"]


def cmd_status(api: client.ApiClient) -> None:
    core = client.CoreV1Api(api)
    phases: dict[str, collections.Counter] = collections.defaultdict(collections.Counter)
    for pod in core.list_pod_for_all_namespaces().items:
        phases[pod.metadata.namespace][pod.status.phase] += 1
    vr = collections.Counter(r["metadata"]["namespace"] for r in _reports(api, "vulnerabilityreports"))
    sb = collections.Counter(r["metadata"]["namespace"] for r in _reports(api, "sbomreports"))
    for ns in sorted(set(phases) | set(vr) | set(sb)):
        print(f"{ns:<22} pods={dict(phases[ns])} vulnerabilityreports={vr[ns]} sbomreports={sb[ns]}")


def cmd_reports(api: client.ApiClient, namespace: str | None) -> None:
    for r in sorted(_reports(api, "vulnerabilityreports", namespace), key=lambda x: x["metadata"]["namespace"]):
        rep, s = r["report"], r["report"].get("summary", {})
        image = f"{rep['artifact'].get('repository')}:{rep['artifact'].get('tag')}"
        print(
            f"{r['metadata']['namespace']:<16} {r['metadata']['name'][:52]:<52} {image[:45]:<45} "
            f"C={s.get('criticalCount', 0)} H={s.get('highCount', 0)} M={s.get('mediumCount', 0)} "
            f"L={s.get('lowCount', 0)} ts={rep.get('updateTimestamp')}"
        )


def cmd_logs(api: client.ApiClient, namespace: str, selector: str, tail: int) -> None:
    core = client.CoreV1Api(api)
    for pod in core.list_namespaced_pod(namespace, label_selector=selector).items:
        print(f"--- {pod.metadata.name}")
        print(core.read_namespaced_pod_log(pod.metadata.name, namespace, tail_lines=tail))


def cmd_wait_reports(api: client.ApiClient, count: int, timeout: int) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        n = len(_reports(api, "vulnerabilityreports"))
        if n >= count:
            print(f"{n} vulnerabilityreports present")
            return
        time.sleep(15)
    sys.exit(f"timeout: only {len(_reports(api, 'vulnerabilityreports'))} vulnerabilityreports after {timeout}s")


def cmd_set_image(api: client.ApiClient, namespace: str, deployment: str, container: str, image: str) -> None:
    body = {"spec": {"template": {"spec": {"containers": [{"name": container, "image": image}]}}}}
    client.AppsV1Api(api).patch_namespaced_deployment(deployment, namespace, body)
    print(f"deployment {namespace}/{deployment} container {container} -> {image}")


def cmd_annotate(api: client.ApiClient, namespace: str, assignment: str) -> None:
    if assignment.endswith("-"):
        annotations = {assignment[:-1]: None}
    else:
        key, value = assignment.split("=", 1)
        annotations = {key: value}
    client.CoreV1Api(api).patch_namespace(namespace, {"metadata": {"annotations": annotations}})
    print(f"namespace {namespace} annotations {annotations}")


def cmd_scale(api: client.ApiClient, namespace: str, kind: str, name: str, replicas: str) -> None:
    apps = client.AppsV1Api(api)
    body = {"spec": {"replicas": int(replicas)}}
    if kind == "StatefulSet":
        apps.patch_namespaced_stateful_set_scale(name, namespace, body)
    else:
        apps.patch_namespaced_deployment_scale(name, namespace, body)
    print(f"{kind} {namespace}/{name} scaled to {replicas}")


def cmd_pods(api: client.ApiClient, namespace: str) -> None:
    for pod in client.CoreV1Api(api).list_namespaced_pod(namespace).items:
        statuses = pod.status.container_statuses or []
        ready = sum(1 for c in statuses if c.ready)
        restarts = sum(c.restart_count for c in statuses)
        print(f"{pod.metadata.name:<55} {pod.status.phase:<10} ready={ready}/{len(statuses)} restarts={restarts}")


def _first_pod(api: client.ApiClient, namespace: str, selector: str) -> str:
    pods = [
        p
        for p in client.CoreV1Api(api).list_namespaced_pod(namespace, label_selector=selector).items
        if p.status.phase == "Running" and p.metadata.deletion_timestamp is None
    ]
    if not pods:
        sys.exit(f"no running pod for {selector} in {namespace}")
    return pods[0].metadata.name


def cmd_exec(api: client.ApiClient, namespace: str, selector: str, container: str, command: list[str]) -> None:
    from kubernetes.stream import stream

    pod = _first_pod(api, namespace, selector)
    resp = stream(
        client.CoreV1Api(api).connect_get_namespaced_pod_exec,
        pod,
        namespace,
        container=container,
        command=command,
        stderr=True,
        stdin=False,
        stdout=True,
        tty=False,
        _preload_content=False,
    )
    resp.run_forever(timeout=600)
    sys.stdout.write(resp.read_stdout())
    err = resp.read_stderr()
    if err:
        sys.stderr.write(err)
    code = resp.returncode
    resp.close()
    if code:
        sys.exit(code)


def cmd_restart(api: client.ApiClient, namespace: str, deployment: str) -> None:
    stamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    body = {"spec": {"template": {"metadata": {"annotations": {"kubectl.kubernetes.io/restartedAt": stamp}}}}}
    client.AppsV1Api(api).patch_namespaced_deployment(deployment, namespace, body)
    print(f"deployment {namespace}/{deployment} restarted at {stamp}")


def cmd_wait_ready(api: client.ApiClient, namespace: str, selector: str, timeout: int) -> None:
    core = client.CoreV1Api(api)
    deadline = time.time() + timeout
    while time.time() < deadline:
        pods = [p for p in core.list_namespaced_pod(namespace, label_selector=selector).items
                if p.metadata.deletion_timestamp is None]
        if pods and all(
            p.status.phase == "Running" and all(c.ready for c in (p.status.container_statuses or [])) for p in pods
        ):
            print(f"{len(pods)} pod(s) ready for {selector}")
            return
        time.sleep(5)
    sys.exit(f"timeout waiting for {selector} in {namespace}")


def cmd_job_status(api: client.ApiClient, namespace: str, name: str) -> None:
    job = client.BatchV1Api(api).read_namespaced_job(name, namespace)
    s = job.status
    print(f"job {namespace}/{name} succeeded={s.succeeded} failed={s.failed} active={s.active}")


def main() -> None:
    api = connect()
    command, args = sys.argv[1], sys.argv[2:]
    if command == "apply":
        cmd_apply(api, args)
    elif command == "delete":
        cmd_delete(api, *args)
    elif command == "status":
        cmd_status(api)
    elif command == "reports":
        cmd_reports(api, args[0] if args else None)
    elif command == "logs":
        cmd_logs(api, args[0], args[1], int(args[2]) if len(args) > 2 else 100)
    elif command == "wait-reports":
        cmd_wait_reports(api, int(args[0]), int(args[1]) if len(args) > 1 else 1800)
    elif command == "set-image":
        cmd_set_image(api, *args)
    elif command == "annotate":
        cmd_annotate(api, *args)
    elif command == "scale":
        cmd_scale(api, *args)
    elif command == "pods":
        cmd_pods(api, args[0])
    elif command == "exec":
        cmd_exec(api, args[0], args[1], args[2], args[3:])
    elif command == "restart":
        cmd_restart(api, *args)
    elif command == "wait-ready":
        cmd_wait_ready(api, args[0], args[1], int(args[2]) if len(args) > 2 else 600)
    elif command == "job-status":
        cmd_job_status(api, *args)
    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main()

# trivy-secobserve-operator

Kubernetes operator that forwards the results of the [Trivy Operator](https://github.com/aquasecurity/trivy-operator)
to [SecObserve](https://github.com/SecObserve/SecObserve) — and optionally archives them in a GCS bucket.

It is the SecObserve counterpart of [trivy-dojo-report-operator](https://github.com/telekom-mms/trivy-dojo-report-operator)
(DefectDojo), but does one thing more: it **joins** the `VulnerabilityReport` with the `SbomReport` of the same
workload into **one CycloneDX document**. SecObserve therefore gets the same data as from a
`trivy image --format cyclonedx` scan:

* vulnerabilities **with dependency paths** (e.g. `image → vendor/…/geoipupdate → github.com/maxmind/geoipupdate → stdlib`),
  so SecObserve rules can match on `origin_component_dependencies`,
* components **with licenses**, so SecObserve license policies work,
* image name/tag/digest and Kubernetes cluster/namespace as origin.

```
Trivy Operator ──► VulnerabilityReport ┐
                   SbomReport ─────────┴─► trivy-secobserve-operator ──► CycloneDX ──► SecObserve (import API)
                                                                              └──────► GCS bucket (optional)
```

## How it works

* kopf watches `vulnerabilityreports`, `sbomreports` (aquasecurity.github.io/v1alpha1) and `namespaces`.
  The handlers only maintain an in-memory index; **the operator never writes to the cluster** (read-only RBAC).
* A single worker fetches the reports fresh from the API, merges them (join on the package URL), stores the
  CycloneDX file and uploads it to `POST /api/import/file_upload_observations_by_name/`.
* One SecObserve **vulnerability check per (product, branch, service)**, with a stable file name
  `trivy-operator_<cluster>_<service>.cdx.json`. SecObserve resolves findings that disappear between two uploads.
* **Dedupe:** the same image in several workloads of a namespace (e.g. 7 CronJobs with the same php-cli image) is
  uploaded once. During a rolling update the report of the new ReplicaSet wins (also when the old one is re-scanned).
* **Different images, same service** (e.g. `php:8.1-fpm` in a Deployment and `php:8.1-cli` in a CronJob, both
  service `php`): they are combined into one upload (union of components and vulnerabilities, a warning is logged)
  instead of overwriting each other on every re-scan. Use `SERVICE_NAME_TEMPLATE` to get separate services.
  If the report of one of them disappears, the service is uploaded without it only after `REMOVAL_GRACE_SECONDS`:
  at `scannerReportTTL` the Trivy Operator deletes a report and creates it again a few minutes later.
* **Retries:** failed uploads are retried with exponential backoff (30 s … `MAX_BACKOFF_SECONDS`).
* **Throttling:** a re-scan of an unchanged image (Trivy Operator `scannerReportTTL`) is uploaded at most every
  `MIN_RESYNC_SECONDS`; a new image digest is uploaded immediately.
* **SBOM missing?** The operator waits `SBOM_WAIT_SECONDS` for the `SbomReport`, then uploads the vulnerabilities
  alone (synthetic components, no dependency graph) and re-uploads once the SBOM arrives.
* **Vanished services** (optional, `RECONCILE_ENABLED`): services whose workloads are gone for
  `RECONCILE_GRACE_SECONDS` get an empty upload, which resolves their findings. Based on the vulnerability checks
  in SecObserve (filtered by this cluster's file name prefix), so it also works after an operator restart and never
  touches imports from other clusters or CI pipelines.

## Mapping to SecObserve

| SecObserve | Default | Override per namespace |
|---|---|---|
| Product | `PRODUCT_NAME_TEMPLATE` = `{namespace}` | annotation `secobserve.io/product` |
| Product group (for new products) | `PRODUCT_GROUP` | annotation `secobserve.io/product-group` |
| Branch / version | `BRANCH_NAME_TEMPLATE` (empty) | annotation `secobserve.io/branch` |
| Service | `SERVICE_NAME_TEMPLATE` = `{image_name}` | – |

For groups of namespaces there is a central mapping, `NAMESPACE_RULES` (Helm: `mapping.namespaceRules`), e.g. to put all
infrastructure namespaces into their own product group without annotating each of them. The first rule whose `match`
regex matches the whole namespace name wins; `product` and `branch` are templates, unset fields use the defaults:

```yaml
mapping:
  productGroup: "Pimcore Installationen"          # default for customer namespaces
  namespaceRules:
    - match: "argocd|cert-manager|ingress-nginx|monitoring|secobserve.*|trivy-system"
      productGroup: "CORS Infrastruktur"
```

Precedence: namespace annotation > first matching rule > global default.

Annotations, not labels: SecObserve names like `Shop Prod` contain spaces, label values cannot.
Templates are `str.format` strings with the fields `cluster`, `namespace`, `registry`, `repository`, `image_name`,
`tag`, `digest`, `container`, `resource_kind`, `resource_name` (no attribute access, no `eval`).

Namespaces: `EXCLUDE_NAMESPACES` are ignored; label `secobserve.io/enabled: "false"` opts a namespace out; with
`REQUIRE_NAMESPACE_LABEL=true` only namespaces with `secobserve.io/enabled: "true"` (or a product annotation) are handled.

Products that do not exist are created (`PRODUCT_AUTO_CREATE`), in the given product group — that is how SecObserve
product-group rules and license policies apply automatically to new namespaces.

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: shop-prod
  annotations:
    secobserve.io/product: "Shop Prod"
    secobserve.io/product-group: "Pimcore Installationen"
```

## Configuration

| Variable | Default | |
|---|---|---|
| `SECOBSERVE_API_URL` | – (required) | e.g. `https://secobserve-backend.example.com/api` |
| `SECOBSERVE_API_TOKEN` | – (required) | API token of a SecObserve user (`Authorization: APIToken …`) |
| `SECOBSERVE_VERIFY_SSL` | `true` | |
| `SECOBSERVE_TIMEOUT_SECONDS` | `300` | large images take a few seconds to import |
| `CLUSTER_NAME` | `default` | distinct per cluster! used in file names, storage path and as Kubernetes cluster |
| `PRODUCT_NAME_TEMPLATE` / `PRODUCT_GROUP` / `PRODUCT_AUTO_CREATE` | `{namespace}` / – / `true` | |
| `SERVICE_NAME_TEMPLATE` / `BRANCH_NAME_TEMPLATE` | `{image_name}` / – | |
| `REQUIRE_NAMESPACE_LABEL` / `EXCLUDE_NAMESPACES` | `false` / `kube-system,kube-public,kube-node-lease,trivy-system` | |
| `NAMESPACE_RULES` | – | JSON list of `{"match", "product", "productGroup", "branch"}`, see above |
| `SUPPRESS_LICENSES` | `false` | do not import components/licenses |
| `MIN_RESYNC_SECONDS` | `21600` | |
| `SBOM_WAIT_SECONDS` | `120` | |
| `REMOVAL_GRACE_SECONDS` | `900` | one image of a combined service is gone: wait for it to come back (re-scan) |
| `WORKER_TICK_SECONDS` / `MAX_BACKOFF_SECONDS` | `5` / `1800` | |
| `GCS_BUCKET` / `GCS_PREFIX` | – / `trivy-secobserve` | `gs://<bucket>/<prefix>/<cluster>/<namespace>/<service>/<digest>/<timestamp>-<content-hash>.cdx.json`, append-only |
| `LOCAL_STORAGE_DIR` | – | same layout on a local disk (tests) |
| `RECONCILE_ENABLED` / `RECONCILE_INTERVAL_SECONDS` / `RECONCILE_GRACE_SECONDS` / `RECONCILE_STARTUP_DELAY_SECONDS` | `false` / `3600` / `7200` / `600` | |
| `LOG_LEVEL` | `INFO` | |

## Requirements on the Trivy Operator side

* `operator.vulnerabilityScannerEnabled: true` and `operator.sbomGenerationEnabled: true` (both default).
* Recommended: `operator.builtInTrivyServer: true` (vulnerability DB is downloaded once instead of per scan job).
* `operator.scannerReportTTL` (default `24h`) controls how often unchanged images are re-scanned with a fresh DB.
* Reports are Kubernetes objects and limited to **3 MiB**. Debian images that keep build dependencies (official
  `php:*`, many app images) contain `linux-libc-dev` with ~8000 kernel CVEs (report ~45 MB): the Trivy Operator then
  fails with `Request entity too large` and writes **no report at all** for the pod. Ignore the package (kernel
  headers only, containers run on the node's kernel):
  ```yaml
  trivy:
    ignorePolicy: |
      package trivy
      import rego.v1
      default ignore := false
      ignore if input.PkgName == "linux-libc-dev"
  ```
* Scan job resources: the default limit (500M) gets scans of larger images OOMKilled, the default `trivy.timeout`
  (5m) is too short when several scan jobs share a node. See [hack/minikube/trivy-operator-values.yaml](hack/minikube/trivy-operator-values.yaml).

## Deployment (Helm)

Images: `ghcr.io/cors-gmbh/trivy-secobserve-operator:<version>` (linux/amd64, linux/arm64), built by CI for every tag
`v<version>`. The chart is not published separately; use it from the tag, e.g. as an ArgoCD git source with
`path: charts/trivy-secobserve-operator` and `targetRevision: v<version>`.

```bash
helm upgrade --install trivy-secobserve-operator charts/trivy-secobserve-operator -n secobserve-operator --create-namespace \
  --set secobserve.apiUrl=https://secobserve-backend.example.com/api \
  --set secobserve.existingSecret=trivy-secobserve-token \
  --set clusterName=prod-gke \
  --set mapping.productGroup="Pimcore Installationen" \
  --set storage.gcsBucket=<bucket> \
  --set serviceAccount.annotations."iam\.gke\.io/gcp-service-account"=trivy-secobserve@<project>.iam.gserviceaccount.com \
  --set reconcile.enabled=true
```

GCS uses Application Default Credentials — on GKE via Workload Identity (the GSA needs `roles/storage.objectCreator`
on the bucket). A bucket lifecycle rule handles retention.

The archive is append-only: objects are created with `ifGenerationMatch=0` and never overwritten (overwriting would
need `storage.objects.delete`). The content hash in the name makes an operator restart write nothing new, while a
changed document for the same scan (e.g. the SBOM arrived later) becomes a second object. A failing archive is logged
as error and shown as `last_archive_error`, but does not stop the uploads to SecObserve.

The SecObserve user needs permission to create products (in the product group) and to import observations.

## Development

```bash
uv sync --extra gcs
uv run pytest            # unit tests, no cluster needed
uv run ruff check src tests && uv run ruff format --check src tests

# merge exported reports (kubectl get vulnerabilityreports/sbomreports -o json) without a cluster
uv run trivy-secobserve convert --vulnerability-report vrs.json --sbom-report sboms.json --name <report> -o out.cdx.json
# feed exported reports through the operator logic into SecObserve (backfill / config test)
SECOBSERVE_API_URL=... SECOBSERVE_API_TOKEN=... uv run trivy-secobserve replay \
  --vulnerability-reports vrs.json --sbom-reports sboms.json --namespace-annotation secobserve.io/product="Shop Prod"

# run the operator locally against a cluster
KUBECONFIG=... SECOBSERVE_API_URL=... SECOBSERVE_API_TOKEN=... \
  uv run kopf run --standalone --all-namespaces -m trivy_secobserve.operator
```

`hack/minikube/` contains an end-to-end setup on a local minikube profile: test workloads with outdated images
(`workloads.yaml`), Trivy Operator values, a GCS emulator and operator values. `env.sh` and `k8s.py` use their own
kubeconfig and refuse to talk to anything but a local cluster.

## Limitations

* Only `VulnerabilityReport` + `SbomReport`. ConfigAudit / RBAC / ExposedSecret / Infra reports are not forwarded
  (SecObserve has no parser for them; a SARIF conversion would be the way).
* The index lives in memory: after a restart every image is uploaded once more (idempotent in SecObserve).
* Different images that map to the same service are combined; the observations show the image of the primary one
  (long-running workloads first). Use `SERVICE_NAME_TEMPLATE="{image_name}-{container}"` (or similar) to separate them.
* `--standalone`: run exactly one replica.
* The Trivy Operator reports only the CVSS v3 score, no vector (unless `trivy.additionalVulnerabilityReportFields`
  contains `CVSS`, which this operator does not evaluate yet).
* Trivy does not see language runtimes that are compiled from source, as in the official `php`, `python`, `ruby`
  and `node` images (and images built on them): CVEs of PHP itself are **not** reported, only OS packages and the
  packages from lock files (composer, npm, gems, ...). Example: PHP2Shell (CVE-2026-109618/-109619) is not found in
  a PHP 8.1.34 image.

  **Fix in the base image** (tested with Trivy 0.74): Trivy reads SBOM files inside the image and matches
  `pkg:bitnami/php` against the Bitnami vulnerability DB, which tracks upstream PHP versions (Bitnami builds PHP
  from source, too). One line after PHP is built:
  ```dockerfile
  RUN v="$(php -r 'echo PHP_VERSION;')"; mkdir -p /usr/local/share/sbom; \
      printf '{"bomFormat":"CycloneDX","specVersion":"1.5","version":1,"metadata":{"component":{"type":"application","name":"php-runtime","version":"%s","bom-ref":"php-runtime"}},"components":[{"type":"application","name":"php","version":"%s","purl":"pkg:bitnami/php@%s","bom-ref":"pkg:bitnami/php@%s"}],"dependencies":[{"ref":"php-runtime","dependsOn":["pkg:bitnami/php@%s"]}]}\n' \
        "$v" "$v" "$v" "$v" "$v" > /usr/local/share/sbom/php.cdx.json
  ```
  With it, Trivy reports PHP2Shell for 8.1.34 and 8.3.31 and nothing for 8.3.36. `pkg:generic/php` is ignored by
  Trivy. PHP installed via `apk` (`php83`, ...) is matched against the Alpine secdb and works without this.

## License

MIT, see [LICENSE](LICENSE).

# syntax=docker/dockerfile:1
# Alpine with Python from apk instead of python:*-slim: ~33 OS packages instead of a full Debian base (whose
# glibc/util-linux/systemd findings mostly have no fix), no pip, and Trivy sees the interpreter itself as package
# python3 (the official python images build it from source, invisible to Trivy).
FROM alpine:3.23 AS build
RUN apk add --no-cache python3
COPY --from=ghcr.io/astral-sh/uv:0.12.23 /uv /usr/local/bin/uv
WORKDIR /app
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy UV_PYTHON_DOWNLOADS=never UV_PYTHON=/usr/bin/python3
COPY pyproject.toml uv.lock README.md ./
RUN uv sync --frozen --no-dev --extra gcs --no-install-project
COPY src ./src
RUN uv sync --frozen --no-dev --extra gcs --no-editable

FROM alpine:3.23
# apk upgrade: fixes released after the base tag was built; python3-pyc: the root filesystem is read-only.
RUN apk upgrade --no-cache \
 && apk add --no-cache python3 python3-pyc \
 && adduser -D -H -u 10001 trivysec
COPY --from=build /app/.venv /app/.venv
# google-crc32c has no musl wheel and uses its pure Python fallback (~1.5 s per 10 MB, only for the GCS archive).
ENV PATH="/app/.venv/bin:$PATH" PYTHONUNBUFFERED=1 \
    PYTHONWARNINGS="ignore:As the c extension couldn't be imported:RuntimeWarning"
USER 10001
EXPOSE 8080
ENTRYPOINT ["kopf", "run", "--standalone", "--all-namespaces", "--liveness=http://0.0.0.0:8080/healthz", "-m", "trivy_secobserve.operator"]

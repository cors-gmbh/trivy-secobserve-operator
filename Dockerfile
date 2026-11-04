# syntax=docker/dockerfile:1
FROM python:3.12-slim AS build
COPY --from=ghcr.io/astral-sh/uv:0.12.23 /uv /usr/local/bin/uv
WORKDIR /app
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy UV_PYTHON_DOWNLOADS=never
COPY pyproject.toml uv.lock README.md ./
RUN uv sync --frozen --no-dev --extra gcs --no-install-project
COPY src ./src
RUN uv sync --frozen --no-dev --extra gcs --no-editable

FROM python:3.12-slim
RUN useradd --uid 10001 --create-home --user-group trivysec
COPY --from=build /app/.venv /app/.venv
ENV PATH="/app/.venv/bin:$PATH" PYTHONUNBUFFERED=1
USER 10001
EXPOSE 8080
ENTRYPOINT ["kopf", "run", "--standalone", "--all-namespaces", "--liveness=http://0.0.0.0:8080/healthz", "-m", "trivy_secobserve.operator"]

FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV SOVEREIGN_POLICY_PATH=policies/baseline_policy.json
ENV SOVEREIGN_STATE_DIR=state

WORKDIR /app

COPY pyproject.toml README.md ./
COPY src ./src
COPY policies ./policies
COPY schemas ./schemas
COPY governance ./governance
COPY integration ./integration
COPY deployments ./deployments

RUN python -m pip install --no-cache-dir --upgrade pip setuptools wheel \
    && python -m pip install --no-cache-dir --no-build-isolation -e .

EXPOSE 8765

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import json, urllib.request; data=json.load(urllib.request.urlopen('http://127.0.0.1:8765/health', timeout=3)); raise SystemExit(0 if data.get('status') == 'ok' else 1)"

CMD ["python", "-m", "sovereign_ide.cli", "serve", "--host", "0.0.0.0", "--port", "8765", "--workspace-root", "/app"]

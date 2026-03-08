# ──────────────────────────────────────────────
# Vyper Guard — Dockerfile
# ──────────────────────────────────────────────
# Multi-stage build for a minimal production image.
#
#   docker build -t vyper-guard .
#   docker run --rm -v $(pwd):/code vyper-guard analyze /code/vault.vy
#   docker run --rm -v $(pwd):/code vyper-guard analyze /code/vault.vy --fix
# ──────────────────────────────────────────────

# Stage 1: Build
FROM python:3.12-slim AS builder

WORKDIR /app

# Install uv for fast dependency resolution
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

# Copy only what's needed for install (maximise cache)
COPY pyproject.toml uv.lock* ./
COPY src/ src/

# Install the package
RUN uv sync --frozen --no-dev && \
    uv pip install -e . --system

# Stage 2: Runtime
FROM python:3.12-slim AS runtime

# OCI standard labels
LABEL org.opencontainers.image.title="Vyper Guard"
LABEL org.opencontainers.image.description="Static analysis & auto-remediation for Vyper smart contracts"
LABEL org.opencontainers.image.source="https://github.com/preethamak/vyper"
LABEL org.opencontainers.image.authors="preethamak"
LABEL org.opencontainers.image.licenses="MIT"

WORKDIR /app

# Copy installed packages and the tool from builder
COPY --from=builder /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --from=builder /usr/local/bin/vyper-guard /usr/local/bin/vyper-guard
COPY --from=builder /app/src /app/src

# Create a non-root user with explicit UID for k8s compatibility
RUN useradd --create-home --uid 1001 guardian
USER guardian

HEALTHCHECK --interval=60s --timeout=5s --retries=2 \
    CMD vyper-guard version || exit 1

ENTRYPOINT ["vyper-guard"]
CMD ["--help"]

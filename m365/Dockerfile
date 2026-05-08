# syntax=docker/dockerfile:1
FROM python:3.12-slim AS base

LABEL org.opencontainers.image.title="M365 Security Agent" \
      org.opencontainers.image.description="AI agent for monitoring and securing Microsoft 365 tenants" \
      org.opencontainers.image.source="https://github.com/Egoorbis/security_agent"

# Non-root user for security
RUN addgroup --system agent && adduser --system --ingroup agent agent

WORKDIR /app

# Install Python deps
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source
COPY agent/ agent/
COPY rules/ rules/

# Ensure the non-root user owns the files
RUN chown -R agent:agent /app
USER agent

ENTRYPOINT ["python", "-m", "agent.main"]
# Default: run assessment and print report
CMD ["--assess", "--report"]

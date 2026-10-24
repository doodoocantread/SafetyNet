# SafetyWebbing scan image: the PentestGPT agent (FULL_ACCESS) runs ONLY inside this
# container. The container is the real isolation boundary — see ARCHITECTURE.md §2.3.
#
# Build (from repo root):
#   docker build -t safetywebbing-agent ./agent_image
#
# The agent uses the "claude" backend, which shells out to the Claude Code CLI.
# Auth is provided at RUN time: LiveAgentEngine mounts an ephemeral copy of the
# host's Claude Code credentials into the non-root user's home
# (/home/agent/.claude), writable so the CLI can refresh its OAuth token.
# Nothing secret is baked into the image.

FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    CLAUDE_CODE_DISABLE_AUTO_MEMORY=1 \
    CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1 \
    DISABLE_AUTOUPDATER=1

# git: needed to fetch the pinned unified-agent revision.
# nodejs/npm: needed by the Claude Code CLI (the "claude" backend).
# curl, ca-certificates: TLS + node setup. Common pentest scanners (curl) also
# double as agent tools.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        git curl ca-certificates nodejs npm \
    && rm -rf /var/lib/apt/lists/*

# Claude Code CLI (the provider the "claude" backend drives).
RUN npm install -g @anthropic-ai/claude-code \
    && npm cache clean --force

WORKDIR /opt/agent
COPY pyproject.toml ./
COPY pentestgpt_agent ./pentestgpt_agent
RUN pip install .

# Claude Code refuses --dangerously-skip-permissions when running as root (a
# security guard), and the agent needs that flag to run tools autonomously. So
# the container runs as a non-root user. Credentials are mounted into this
# user's home (/home/agent/.claude) by LiveAgentEngine, not into /root.
RUN useradd --create-home --uid 1000 agent \
    && mkdir -p /work/runs /work/agent-workspaces \
    && chown -R agent:agent /work /home/agent
ENV HOME=/home/agent
USER agent
WORKDIR /work

ENTRYPOINT ["pentestgpt-agent"]

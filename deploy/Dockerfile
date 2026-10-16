# The runner image: Node 24, bubblewrap and socat for the boxes, python3 for validators a host app may run in a box, the pinned
# CLIs, one non-root uid that owns /homes, and harnessbox at /opt/harnessbox. Build from the repository root:
#   docker build -f deploy/Dockerfile -t harnessbox-runner .
# A host app builds FROM this image, copies its runner script (which imports /opt/harnessbox/src/index.mjs) and sets CMD.
# The CLIs never update themselves inside a box (the adapters' env); a new version is a rebuild with new build args, then detect().
FROM node:24-bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends tini ca-certificates bubblewrap socat python3 curl \
 && rm -rf /var/lib/apt/lists/*
ARG CLAUDE_CODE_VERSION=2.1.300
ARG CODEX_VERSION=0.162.1
ARG GROK_VERSION=1.0.52
RUN npm install -g --no-audit --no-fund @anthropic-ai/claude-code@${CLAUDE_CODE_VERSION} @openai/codex@${CODEX_VERSION} && npm cache clean --force
# Grok: xAI's installer downloads into $HOME/.grok/downloads and, as root, links /usr/local/bin/grok and agent there; only the binary
# is kept, on PATH.
RUN h=$(mktemp -d) && HOME=$h bash -c "curl -fsSL https://x.ai/cli/install.sh | bash -s ${GROK_VERSION}" \
 && b=$(readlink -f "$(ls -d $h/.grok/downloads/grok-linux-* | head -1)") && rm -f /usr/local/bin/grok /usr/local/bin/agent \
 && cp "$b" /usr/local/bin/grok && chmod 755 /usr/local/bin/grok && rm -rf $h
# Each CLI starts with an empty HOME and has the options its adapter needs; bwrap knows --size (0.8+).
RUN h=$(mktemp -d) && export HOME=$h PATH=/usr/local/bin:/usr/bin:/bin \
 && claude --version && codex --version && grok --version \
 && claude --help | grep -q -- --restricted && codex exec --help | grep -q -- '--disable <FEATURE>' && grok --help | grep -q -- streaming-json \
 && bwrap --help | grep -q -- --size && rm -rf $h
RUN groupadd -g 10011 harnessbox && useradd -u 10011 -g 10011 -M -d /nonexistent -s /usr/sbin/nologin harnessbox \
 && install -d -o 10011 -g 10011 -m 700 /homes
COPY src /opt/harnessbox/src
COPY deploy/probe.mjs /opt/harnessbox/deploy/probe.mjs
COPY package.json /opt/harnessbox/package.json
ENV NODE_ENV=production
USER 10011:10011
WORKDIR /opt/harnessbox
ENTRYPOINT ["tini", "--"]
CMD ["node", "/opt/harnessbox/deploy/probe.mjs"]

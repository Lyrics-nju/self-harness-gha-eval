# Dedicated generic pre-provisioned linux/amd64 builder. The controller refuses
# execution until BASE_IMAGE, Node archive checksum and Corepack are frozen.
# No apt/NodeSource fallback; the base must already contain build prerequisites.
ARG BASE_IMAGE
FROM --platform=linux/amd64 ${BASE_IMAGE}
ARG NODE_ARCHIVE_SHA256
ARG NODE_VERSION
ARG COREPACK_VERSION
COPY inputs/node.tar.xz /inputs/node.tar.xz
COPY source/ /source/
COPY tooling/scripts/m1c_runtime_artifact.py tooling/scripts/m1c_runtime_builder.py tooling/scripts/public_secret_scan.py /tooling/scripts/
RUN test -n "$NODE_ARCHIVE_SHA256" && test -n "$COREPACK_VERSION" \
    && printf '%s  /inputs/node.tar.xz\n' "$NODE_ARCHIVE_SHA256" | sha256sum -c - \
    && mkdir /opt/pinned-node \
    && tar -xJf /inputs/node.tar.xz -C /opt/pinned-node --strip-components=1 \
    && test "$(/opt/pinned-node/bin/node --version)" = "$NODE_VERSION"
# PATH applies only to the builder. It is never exported to a task container.
ENV PATH=/opt/pinned-node/bin:${PATH}
RUN test "$(corepack --version)" = "$COREPACK_VERSION" \
    && cd /tooling && python3 -m scripts.m1c_runtime_builder --preflight /source \
    && cd /source \
    && test "$(git rev-parse HEAD)" = b150a551b8d465e31e418e1b2eaf5e79bbb7d28e \
    && test -z "$(git status --porcelain)" \
    && test "$(node -p 'require("./package.json").packageManager')" = pnpm@11.7.0 \
    && test "${NODE_OPTIONS+x}" != x \
    && corepack enable && test "$(pnpm --version)" = 11.7.0 \
    && pnpm install --frozen-lockfile \
    && pnpm run build \
    && cd /tooling \
    && python3 -m scripts.m1c_runtime_builder /source /opt/pinned-node /output
# /output is exported at runner setup; no formal container downloads this image
# or its dependencies. No benchmark data, model secrets or task state is input.

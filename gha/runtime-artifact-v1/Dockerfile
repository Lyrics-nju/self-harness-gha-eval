# Toolchain image ONLY. No DSH source/install/build is an image-creation step.
ARG BASE_IMAGE
FROM --platform=linux/amd64 ${BASE_IMAGE}
ARG NODE_ARCHIVE_SHA256
ARG NODE_VERSION
ARG COREPACK_INTEGRITY
ARG PNPM_INTEGRITY
COPY inputs/ /inputs/
COPY scripts/ /tooling/scripts/
COPY gha/runtime-artifact-v1/Dockerfile /tooling/gha/runtime-artifact-v1/Dockerfile
COPY configs/m1c_runtime_prebuild_v1.json /tooling/configs/m1c_runtime_prebuild_v1.json
RUN test -n "$NODE_ARCHIVE_SHA256" \
    && printf '%s  /inputs/node.tar.xz\n' "$NODE_ARCHIVE_SHA256" | sha256sum -c - \
    && python3 -c 'import base64,hashlib,os,pathlib; [(_ for _ in ()).throw(RuntimeError("PACKAGE_INTEGRITY_MISMATCH")) if "sha512-"+base64.b64encode(hashlib.sha512(pathlib.Path("/inputs/"+n).read_bytes()).digest()).decode()!=os.environ[k] else None for n,k in [("corepack.tgz","COREPACK_INTEGRITY"),("pnpm.tgz","PNPM_INTEGRITY")]]' \
    && mkdir /opt/pinned-node \
    && tar -xJf /inputs/node.tar.xz -C /opt/pinned-node --strip-components=1 \
    && test "$(/opt/pinned-node/bin/node --version)" = "$NODE_VERSION"
# PATH applies only to the builder. It is never exported to a task container.
ENV PATH=/opt/pinned-node/bin:${PATH}
RUN npm install --global --offline --ignore-scripts /inputs/corepack.tgz \
    && test "$(corepack --version)" = 0.33.0 \
    && corepack enable \
    && corepack install -g "pnpm@11.7.0+sha512.$(python3 -c 'import hashlib; print(hashlib.sha512(open("/inputs/pnpm.tgz","rb").read()).hexdigest())')" \
    && test "$(pnpm --version)" = 11.7.0
# Controller must verify final image identity and capacity before DSH build.

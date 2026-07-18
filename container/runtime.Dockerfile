ARG RUST_IMAGE=rust:1.97-bookworm@sha256:77fac8b98f9f46062bb680b6d25d5bcaabfc400143952ebc572e924bcbedc3fa
ARG PIXI_IMAGE=ghcr.io/prefix-dev/pixi:0.54.2@sha256:5642b666f269ec0c34a466d2e8e091b76b9346b441c9b05349d72a79befc03c2
ARG NODE_IMAGE=node:24.16.0-bookworm-slim@sha256:2c87ef9bd3c6a3bd4b472b4bec2ce9d16354b0c574f736c476489d09f560a203

FROM ${RUST_IMAGE} AS rust-build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/usr/local/cargo/git,sharing=locked \
    --mount=type=cache,target=/src/target,sharing=locked \
    cargo build --release --locked --bin shennong-runtime --bin shennong-ide-gateway \
    && install -D -m 0755 target/release/shennong-runtime /out/shennong-runtime \
    && install -D -m 0755 target/release/shennong-ide-gateway /out/shennong-ide-gateway

FROM ${PIXI_IMAGE} AS pixi

FROM ${NODE_IMAGE}
ARG RSTUDIO_DEB_URL=https://download2.rstudio.org/server/jammy/amd64/rstudio-server-2026.07.0-139-amd64.deb
ARG RSTUDIO_DEB_SHA256=e7b310c9e46811635b8dea8df82c729686c3a78f35cfa7767d9567e30f528465
ARG JUPYTERLAB_VERSION=4.6.1

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       ca-certificates curl python3 python3-pip python3-venv r-base gdebi-core \
    && curl --fail --show-error --location "${RSTUDIO_DEB_URL}" --output /tmp/rstudio.deb \
    && echo "${RSTUDIO_DEB_SHA256}  /tmp/rstudio.deb" | sha256sum --check --strict \
    && gdebi --non-interactive /tmp/rstudio.deb \
    && python3 -m venv /opt/jupyter \
    && /opt/jupyter/bin/pip install --no-cache-dir "jupyterlab==${JUPYTERLAB_VERSION}" \
    && ln -s /opt/jupyter/bin/jupyter /usr/local/bin/jupyter \
    && groupadd --gid 65532 shennong \
    && useradd --uid 65532 --gid 65532 --home-dir /workspace/.shennong/home --no-create-home --shell /usr/sbin/nologin shennong \
    && mkdir -p /opt/shennong/bin /opt/shennong/etc /workspace /data /run/shennong /var/lib/shennong-runtime \
    && chown 65532:65532 /workspace /data /var/lib/shennong-runtime \
    && rm -f /tmp/rstudio.deb \
    && rm -rf /var/lib/apt/lists/*

COPY --from=pixi /usr/local/bin/pixi /usr/local/bin/pixi
COPY --from=rust-build /out/shennong-runtime /usr/local/bin/shennong-runtime
COPY --from=rust-build /out/shennong-ide-gateway /opt/shennong/bin/shennong-ide-gateway
COPY container/worker/job_entrypoint.py /opt/shennong/bin/job_entrypoint.py
COPY container/worker/scan_artifacts.py /opt/shennong/bin/scan_artifacts.py
COPY container/ide/launch_ide.py /opt/shennong/bin/launch_ide.py
COPY container/ide/rstudio-database.conf /opt/shennong/etc/rstudio-database.conf
COPY container/runtime-entrypoint.sh /usr/local/bin/shennong-runtime-entrypoint
RUN chmod 0444 /opt/shennong/etc/rstudio-database.conf \
    && chmod 0555 /opt/shennong/etc \
       /opt/shennong/bin/job_entrypoint.py \
       /opt/shennong/bin/scan_artifacts.py \
       /opt/shennong/bin/launch_ide.py \
       /opt/shennong/bin/shennong-ide-gateway \
       /usr/local/bin/shennong-runtime-entrypoint

ENV PYTHONDONTWRITEBYTECODE=1 \
    HOME=/workspace/.shennong/home \
    SHENNONG_CONFIG_DIR=/config \
    SHENNONG_DATA_DIR=/var/lib/shennong-runtime
WORKDIR /workspace
VOLUME ["/data"]
EXPOSE 7000 18080
ENTRYPOINT ["/usr/local/bin/shennong-runtime-entrypoint"]
CMD ["shennong-runtime", "serve"]
HEALTHCHECK --interval=10s --timeout=3s --retries=12 CMD ["shennong-runtime", "healthcheck"]

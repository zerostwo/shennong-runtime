# syntax=docker/dockerfile:1.7
# The worker is a release artifact, so every IDE build must supply its digest.
ARG RUST_IMAGE=rust:1.97-bookworm@sha256:77fac8b98f9f46062bb680b6d25d5bcaabfc400143952ebc572e924bcbedc3fa
ARG WORKER_IMAGE

FROM ${RUST_IMAGE} AS gateway-build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release --locked --bin shennong-ide-gateway

FROM ${WORKER_IMAGE}
USER root
# Posit RStudio Server 2026.07.0+139, Ubuntu 22 amd64 official package.
ARG RSTUDIO_DEB_URL=https://download2.rstudio.org/server/jammy/amd64/rstudio-server-2026.07.0-139-amd64.deb
ARG RSTUDIO_DEB_SHA256=e7b310c9e46811635b8dea8df82c729686c3a78f35cfa7767d9567e30f528465
ARG JUPYTERLAB_VERSION=4.6.1
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl python3-pip python3-venv gdebi-core \
    && curl --fail --show-error --location "${RSTUDIO_DEB_URL}" --output /tmp/rstudio.deb \
    && echo "${RSTUDIO_DEB_SHA256}  /tmp/rstudio.deb" | sha256sum --check --strict \
    && gdebi --non-interactive /tmp/rstudio.deb \
    && python3 -m venv /opt/jupyter \
    && /opt/jupyter/bin/pip install --no-cache-dir "jupyterlab==${JUPYTERLAB_VERSION}" \
    && ln -s /opt/jupyter/bin/jupyter /usr/local/bin/jupyter \
    && rm -rf /tmp/rstudio.deb /var/lib/apt/lists/*
COPY --from=gateway-build /src/target/release/shennong-ide-gateway /opt/shennong/bin/shennong-ide-gateway
COPY container/ide/launch_ide.py /opt/shennong/bin/launch_ide.py
COPY --chown=0:0 container/ide/rstudio-database.conf /opt/shennong/etc/rstudio-database.conf
RUN chmod 0444 /opt/shennong/etc/rstudio-database.conf \
    && chmod 0555 /opt/shennong/etc \
    /opt/shennong/bin/shennong-ide-gateway \
    /opt/shennong/bin/launch_ide.py
USER 65532:65532
WORKDIR /workspace
ENTRYPOINT []
# Fail closed when run outside Runtime: the supervisor requires a Session kind,
# proxy path, gateway digest, and gateway listen address before starting an IDE.
CMD ["python3", "/opt/shennong/bin/launch_ide.py"]

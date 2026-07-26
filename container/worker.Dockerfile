# syntax=docker/dockerfile:1.7
# Reviewed V1 manifest-list digests; update deliberately with dependency review.
ARG PIXI_IMAGE=ghcr.io/prefix-dev/pixi:0.54.2@sha256:5642b666f269ec0c34a466d2e8e091b76b9346b441c9b05349d72a79befc03c2
ARG BASE_IMAGE=debian:bookworm-slim@sha256:7b140f374b289a7c2befc338f42ebe6441b7ea838a042bbd5acbfca6ec875818

FROM ${PIXI_IMAGE} AS pixi
FROM ${BASE_IMAGE}
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       ca-certificates python3 r-base \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 65532 shennong \
    && useradd --uid 65532 --gid 65532 --home-dir /workspace/.shennong/home --no-create-home --shell /usr/sbin/nologin shennong \
    && mkdir -p /opt/shennong/bin /workspace \
    && chown 65532:65532 /workspace
COPY --from=pixi /usr/local/bin/pixi /usr/local/bin/pixi
COPY container/worker/job_entrypoint.py /opt/shennong/bin/job_entrypoint.py
COPY container/worker/scan_artifacts.py /opt/shennong/bin/scan_artifacts.py
COPY container/worker/read_artifact.py /opt/shennong/bin/read_artifact.py
RUN chmod 0555 /opt/shennong/bin/job_entrypoint.py \
    /opt/shennong/bin/read_artifact.py \
    /opt/shennong/bin/scan_artifacts.py
ENV PYTHONDONTWRITEBYTECODE=1 \
    HOME=/workspace/.shennong/home
USER 65532:65532
WORKDIR /workspace
ENTRYPOINT ["python3", "/opt/shennong/bin/job_entrypoint.py"]

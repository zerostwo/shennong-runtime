# syntax=docker/dockerfile:1.7
ARG RUST_IMAGE=rust:1.97-bookworm@sha256:77fac8b98f9f46062bb680b6d25d5bcaabfc400143952ebc572e924bcbedc3fa
ARG RUNTIME_IMAGE=debian:bookworm-slim@sha256:7b140f374b289a7c2befc338f42ebe6441b7ea838a042bbd5acbfca6ec875818

FROM ${RUST_IMAGE} AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release --locked --bin shennong-runtime

FROM ${RUNTIME_IMAGE}
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 65532 shennong \
    && useradd --uid 65532 --gid 65532 --home-dir /nonexistent --no-create-home --shell /usr/sbin/nologin shennong \
    && mkdir -p /run/shennong-rootless /var/lib/shennong-runtime \
    && chown 65532:65532 /run/shennong-rootless /var/lib/shennong-runtime
COPY --from=build /src/target/release/shennong-runtime /usr/local/bin/shennong-runtime
USER 65532:65532
EXPOSE 7000
ENTRYPOINT ["/usr/local/bin/shennong-runtime"]
CMD ["serve"]
HEALTHCHECK --interval=10s --timeout=3s --retries=12 CMD ["/usr/local/bin/shennong-runtime", "healthcheck"]

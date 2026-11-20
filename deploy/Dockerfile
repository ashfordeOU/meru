# meru container image. Build from a directory that holds both checkouts side by side:
#
#   parent/
#     meru/        (this repository)
#     kshana-pro/  (ashfordeOU/kshana-pro)
#
#   docker build -f meru/deploy/Dockerfile -t meru:$(git -C meru rev-parse --short HEAD) parent/
#
# The image holds the stripped binary only: no source, no keys. Keys come from the runtime
# environment (KMS in production, see deploy/README.md). Never push this image to a public
# registry. The same image serves every profile: set MERU_PROFILE=arksa-internal or
# sovereign-contracted at run time and keep the container on a private network only
# (deploy/README.md section 7; 0.0.0.0 inside the container is then allowed with a warning).
FROM rust:1-bookworm AS build
WORKDIR /src
COPY kshana-pro ./kshana-pro
COPY meru ./meru
RUN cd meru && cargo build --release --locked

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --home /var/lib/meru --create-home meru
COPY --from=build /src/meru/target/release/meru /usr/local/bin/meru
USER meru
WORKDIR /var/lib/meru
ENV MERU_ADDR=0.0.0.0:8099 \
    MERU_METER_LOG=/var/lib/meru/meter.jsonl
EXPOSE 8099
ENTRYPOINT ["/usr/local/bin/meru"]

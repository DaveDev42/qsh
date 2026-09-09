# OSS-Fuzz build image for qsh.
#
# base-builder-rust ships a nightly Rust toolchain plus cargo-fuzz
# pre-installed (verification needed against the upstream image at
# submission time — this Dockerfile is drafted from OSS-Fuzz's documented
# Rust integration convention, not from a build run against the real
# oss-fuzz-base/base-builder-rust image).
FROM gcr.io/oss-fuzz-base/base-builder-rust

# aws-lc-sys (pulled in transitively via rustls) needs cmake to build its
# vendored BoringSSL/AWS-LC at compile time — base-builder-rust doesn't
# carry it by default (see README u2).
RUN apt-get update && apt-get install -y --no-install-recommends cmake && rm -rf /var/lib/apt/lists/*

RUN git clone --depth 1 https://github.com/DaveDev42/qsh qsh
COPY build.sh $SRC/

WORKDIR $SRC/qsh

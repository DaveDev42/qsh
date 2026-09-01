# Two identical containers stand in for the campaign's "two machines that
# have never run qsh before" (docs/campaigns/m7-stopwatch.md §3). The build
# stage compiles the working tree so a round measures the commit under test,
# not a published release.
#
# Build context is the repository root, not this directory.

# Pinned to rust-toolchain.toml's channel so the image does not spend a
# round's setup time letting rustup download a second toolchain.
FROM rust:1.97.1-bookworm AS build
WORKDIR /src
COPY . .
RUN cargo build --release -p qsh-cli

FROM debian:bookworm-slim

# procps/lsof/iproute2 are for the facilitator's §3 precondition checks and
# for the subject to see what is listening. None of them are qsh commands —
# §3 forbids warming up with qsh itself before the timer starts.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates procps lsof iproute2 iputils-ping nano \
    && rm -rf /var/lib/apt/lists/*

# README's "First run" types `qsh dave@box`, and `user@` must name the
# account actually running `qsh serve` or the host answers UNSUPPORTED. A
# real `dave` account is what makes the section's literal command work.
RUN useradd --create-home --shell /bin/bash dave

COPY --from=build /src/target/release/qsh /usr/local/bin/qsh

USER dave
WORKDIR /home/dave
ENV HOME=/home/dave
CMD ["sleep", "infinity"]

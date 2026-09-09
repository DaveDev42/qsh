# OSS-Fuzz integration (draft)

This directory holds the three files an OSS-Fuzz project submission needs
(`project.yaml`, `Dockerfile`, `build.sh`) so that `qsh`'s 16 existing
`cargo-fuzz` targets under `fuzz/` (see `fuzz/README.md` and
`docs/campaigns/m8-fuzz.md`) get picked up by OSS-Fuzz's own build and
scheduling infrastructure — continuous fuzzing on Google's fleet, on top
of this repo's own local runs and CI smoke job.

These files are a draft written against OSS-Fuzz's documented Rust
integration convention, not yet validated against a real build inside
`gcr.io/oss-fuzz-base/base-builder-rust`. `scripts/fuzz/oss-fuzz-local.sh`
runs `build.sh` locally (outside the OSS-Fuzz container, against whatever
toolchain is on this machine) as the closest local approximation; it is
not a substitute for a real `infra/helper.py build_image && build_fuzzers`
run against the actual OSS-Fuzz repo checkout.

## Submission is a separate, human action

Nothing under `fuzz/oss-fuzz/` submits anything by itself. Getting `qsh`
onto OSS-Fuzz requires:

- **u1**: fork/clone `google/oss-fuzz`, add a `projects/qsh/` directory
  there containing this directory's three files (copied, not symlinked —
  OSS-Fuzz's own tree is what it builds from), and open a PR against
  `google/oss-fuzz`. `primary_contact` in `project.yaml` must be a real,
  monitored address before that PR goes up — the `<primary-contact@
  example.com>` placeholder here is deliberate; replace it with an
  address a maintainer controls, not committed to this repo's own git
  history if that address is meant to stay private (OSS-Fuzz's project
  directory is itself public). When you do, swap the whole angle-bracketed token — brackets included — for a plain `primary_contact: "you@example.org"` line; the `<...>` form is a placeholder marker, not valid YAML on its own.
- **u2**: validate the build for real before opening the PR —
  `python infra/helper.py build_image qsh && python infra/helper.py
  build_fuzzers qsh` from inside a `google/oss-fuzz` checkout, pointing at
  this repo (or a branch of it) as `main_repo`. That exercises the actual
  `base-builder-rust` image, which this draft has not yet run against.
  Fix whatever the Dockerfile/build.sh comments flag as "verification
  needed" against what that run shows. First `build_fuzzers` failure's
  top suspect: `aws-lc-sys` needing `cmake`, which the Dockerfile now
  installs — confirm it's still there in whatever base-builder-rust
  version is current at submission time.
- **u3**: once the PR merges and OSS-Fuzz starts building `qsh`, monitor
  the project's OSS-Fuzz dashboard and the `primary_contact` inbox for
  build failures and new crash reports — that monitoring is an ongoing
  human commitment, not a one-time setup step.

## Files here

| file | purpose |
|---|---|
| `project.yaml` | OSS-Fuzz project metadata: language, contact, sanitizer/engine/architecture matrix. |
| `Dockerfile` | Build image: clones `main_repo` fresh and layers `build.sh` on top of `base-builder-rust`. |
| `build.sh` | Builds every target `cargo fuzz list` reports (16 today) with `cargo fuzz build -O --debug-assertions` and stages each binary plus its seed corpus zip into `$OUT`. |

`scripts/fuzz/oss-fuzz-local.sh` (repo root) is the local stand-in used to
exercise `build.sh` without an OSS-Fuzz checkout or the Docker image.

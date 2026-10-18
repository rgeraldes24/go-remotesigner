# Copyright 2026 The go-remotesigner Authors.
# SPDX-License-Identifier: Apache-2.0
#
# The remotesigner image: one static binary on distroless static, run as the
# base image's nonroot user (65532:65532), and able to run with a read-only
# root file system. goreleaser builds it for both flavours (.goreleaser.yaml);
# `make image` builds one for this machine. The build context holds the
# binary at <os>/<arch>/<flavour> and the flavour's licence files at
# build/release/<flavour>/ (tools/releasedocs). The image and its entrypoint
# are described in docs/operations/deploy-docker.md.
#
# The base image is pinned by the digest of its multi-platform index;
# Renovate moves the pin.

FROM gcr.io/distroless/static-debian13:nonroot@sha256:e2e927ec666bae08560abb3c55d0659eceabb657f56b6782ab500a9fc7f555e3 AS base

FROM base

ARG TARGETPLATFORM
# FLAVOUR is remotesigner (the default flavour) or remotesigner-consensus (consensus only).
ARG FLAVOUR=remotesigner-consensus
ARG VERSION=dev
ARG REVISION=unknown
ARG CREATED
# LICENSES is the SPDX expression of the licences the flavour's binary links, from build/release/<flavour>.licenses.
ARG LICENSES

LABEL org.opencontainers.image.title="${FLAVOUR}" \
      org.opencontainers.image.description="Remote signer for QRL validator clients" \
      org.opencontainers.image.licenses="${LICENSES}" \
      org.opencontainers.image.vendor="The go-remotesigner Authors" \
      org.opencontainers.image.source="https://github.com/rgeraldes24/go-remotesigner" \
      org.opencontainers.image.documentation="https://github.com/rgeraldes24/go-remotesigner/blob/main/docs/operations/deploy-docker.md" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}" \
      org.opencontainers.image.created="${CREATED}" \
      org.opencontainers.image.base.name="gcr.io/distroless/static-debian13:nonroot" \
      org.opencontainers.image.base.digest="sha256:e2e927ec666bae08560abb3c55d0659eceabb657f56b6782ab500a9fc7f555e3"

COPY --chmod=0555 ${TARGETPLATFORM}/${FLAVOUR} /usr/local/bin/remotesigner
# LICENSE, the flavour's NOTICE, LICENSES/ and third_party_licenses/.
COPY build/release/${FLAVOUR}/ /usr/share/doc/remotesigner/
# /data holds the generated tokens and TLS certificate, the slashing-protection store and the ports file. It is
# created empty, owned by the nonroot user and mode 0700 (a copy of the base image's empty /home/nonroot), so that a
# named volume mounted there starts with that owner and mode.
COPY --from=base --chown=65532:65532 --chmod=0700 /home/nonroot/ /data/

USER 65532:65532
WORKDIR /data
EXPOSE 9000 9001

# The API binds every interface over TLS, with a certificate generated into /data/tls on first start unless one is
# mounted and configured, and the token files are generated into /data. The operator appends the rest: at least
# --http-host-allowlist with the names clients use, then `consensus` and --network; without them the signer refuses
# to start. Arguments given to `docker run` replace CMD, so they name the subcommand themselves.
ENTRYPOINT ["/usr/local/bin/remotesigner", "--data-path=/data", "--http-listen-host=0.0.0.0", "--tls-generate-self-signed"]
CMD ["consensus"]

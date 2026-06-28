#!/usr/bin/env sh
# inspect/run-all.sh — the offline gate (no network): NIP-19, NIP-01 events,
# Schnorr sign/verify, TLV, filters.  Points ASDF at this tree plus a sibling
# secp256k1-fast checkout (or one already in ~/quicklisp/local-projects).
set -e
here=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
export CL_SOURCE_REGISTRY="(:source-registry (:tree \"$here\") (:tree \"$here/..\") :inherit-configuration)"
exec sbcl --non-interactive \
  --eval '(handler-bind ((warning (function muffle-warning))) (asdf:load-system "cl-nostr/test"))' \
  --eval '(uiop:quit (if (ignore-errors (cl-nostr.test:run)) 0 1))'

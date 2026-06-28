# cl-nostr

A from-scratch **Nostr client in Common Lisp.**

It builds and signs **NIP-01 events** (BIP340 Schnorr over secp256k1), gets the
**canonical event-id serialization byte-exact** (verified against real published
events), encodes and decodes the **NIP-19** bech32 entity family
(`npub`/`nsec`/`note` + the TLV `nprofile`/`nevent`/`naddr`), and talks the
relay protocol over **WebSocket** (`wss://`) — a relay connection with
subscriptions, plus a **relay pool** that fans publish/subscribe out across many
relays and de-duplicates the merged stream.

Like its sibling [cl-consensus](../cl-consensus), the point of difference is that
**nothing here wraps a reference client** — the event model, the canonical
serialization, NIP-19 bech32/TLV, and the relay protocol are all implemented in
Lisp. The crypto is the shared, independently-derived
[`secp256k1-fast`](https://github.com/modus-lisp/secp256k1-fast) — whose BIP340
Schnorr *is* Nostr's event-signature scheme.

## ⚠️ Status & disclaimer

Research / educational software. The crypto is optimized for speed, **not**
constant-time side-channel resistance — do not use these keys to hold anything of
value. No warranty (see [LICENSE](LICENSE)).

## What works

- **Keys** — generate / restore a keypair; x-only public keys; `npub`/`nsec`.
- **Events (NIP-01)** — build → canonical-serialize → SHA-256 id → Schnorr-sign;
  verify (id-match **and** signature); JSON in/out; tag helpers (`e`/`p`/…).
  The canonical serializer is **byte-exact** — recomputed ids match real events,
  including multibyte-UTF-8 content.
- **NIP-19** — bech32 codec (no length cap) for `npub`/`nsec`/`note` and the TLV
  entities `nprofile`/`nevent`/`naddr`, with a `decode-entity` dispatcher.
- **Filters (NIP-01)** — ids/authors/kinds/`#`-tags/since/until/limit/search,
  JSON serialization, and local matching (prefix match for ids/authors).
- **Relay** — `wss://` connect (TLS via cl+ssl), `REQ`/`EVENT`/`CLOSE`, and
  dispatch of `EVENT`/`EOSE`/`OK`/`NOTICE`/`CLOSED` to per-subscription callbacks.
- **Pool** — connect to many relays in parallel (timeout-bounded so one slow
  relay can't stall the rest); `pool-publish`, `pool-subscribe` (deduplicated),
  and a blocking `fetch-events` that waits for `EOSE`/timeout.

## Layout

```
cl-nostr.asd            ASDF system
src/
  packages              package + nickname layout
  util                  hex / UTF-8 / SHA-256 / randomness
  keys                  keypair, npub/nsec, Schnorr sign/verify (over secp256k1-fast)
  bech32                NIP-19: bech32 codec + simple & TLV entities
  event                 NIP-01: canonical serialization, id, sign, verify, JSON
  filter                NIP-01 subscription filters (JSON + local matching)
  relay                 one relay: websocket connect + message dispatch
  pool                  multi-relay client: publish + subscribe + fetch
inspect/
  offline-test.lisp     the offline gate (NIP-19/NIP-01 spec + real-world vectors)
  run-all.sh            run it
bin/cl-nostr.lisp       demo: stream the live global feed, verifying each note
```

## Dependencies

Pure SBCL + Quicklisp libs (`ironclad`, `com.inuoe.jzon`, `websocket-driver`,
`cl+ssl`, `bordeaux-threads`) plus **`secp256k1-fast`** (the crypto), which isn't
on Quicklisp. Put it where ASDF can find it — a sibling checkout works with
`run-all.sh`, or symlink it in:

```sh
ln -s /path/to/secp256k1-fast ~/quicklisp/local-projects/secp256k1-fast
ln -s /path/to/cl-nostr       ~/quicklisp/local-projects/cl-nostr
```

## Quick start

```lisp
(ql:quickload "cl-nostr")

;; an identity
(defparameter *kp* (cl-nostr.keys:make-keypair))
(cl-nostr.bech32:npub-encode (cl-nostr.keys:public-hex *kp*))   ; => "npub1..."

;; connect a pool and read the global feed
(defparameter *pool* (cl-nostr.pool:make-pool '("wss://relay.damus.io")))
(cl-nostr.pool:fetch-events
 *pool* (cl-nostr.filter:make-filter :kinds '(1) :limit 5))     ; => (event ...)

;; build, sign, and publish a note
(let ((note (cl-nostr.event:build-event *kp* 1 "hello from cl-nostr")))
  (cl-nostr.pool:pool-publish
   *pool* note
   :on-ok (lambda (relay ok msg)
            (format t "~a: ~:[rejected~;accepted~] ~a~%"
                    (cl-nostr.relay:relay-url relay) ok msg))))
```

Run the offline gate:

```sh
inspect/run-all.sh
# === 24 passed, 0 failed ===
```

Stream the live global feed (generates a throwaway identity, or pass an `nsec1…`):

```sh
sbcl --load bin/cl-nostr.lisp
```

## Validation

`inspect/offline-test.lisp` checks the pure layers against **published vectors**:

- the **NIP-19 spec** examples (`npub`/`nsec` round-trips, `nsec → npub`
  derivation, the canonical `nprofile` TLV);
- the real-world **"Walled gardens"** kind-1 event (fiatjaf) — its id is
  recomputed byte-for-byte and its Schnorr signature verified;
- sign/verify round-trips (incl. a tamper check) and filter matching.

End to end, `bin/cl-nostr.lisp` connects to live relays and verifies the
signature of every note it streams.

## License

MIT.

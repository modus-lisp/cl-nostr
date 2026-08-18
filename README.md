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

Research / educational software. The crypto's secret operations (key generation
and Schnorr signing) are now constant-time on the x86-64/arm64 backend, but only
at the algorithm + field-arithmetic level — a GC'd runtime gives no formal
microarchitectural guarantee. Still unaudited; treat as educational. No warranty
(see [LICENSE](LICENSE)).

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
  and a blocking `fetch-events` that waits for `EOSE`/timeout. `pool-publish-sync`
  **waits for each relay's `OK`** and hands back a `relay-ack` per relay — the only
  evidence an event was really published (see below).
- **Websites (nsite / NIP-5A + Blossom BUD-01/02)** — publish a static site to
  Nostr and resolve one back from nothing but an `npub` and a path.

## Publishing is partial, so the API reports instead of returning a boolean

Two things go wrong constantly when you publish to other people's infrastructure,
and both are silent:

**A send that vanishes.** A WebSocket whose socket has died swallows the frame
without signalling, and a script that publishes and exits has exited before any
relay answered. The relay's `OK` is the *only* evidence. `pool-publish-sync` waits
for it, re-sends to anything still quiet (reconnecting a dropped relay first — a
re-send is free, relays dedupe by event id), and reports per relay: `:accepted`,
`:rejected`, `:no-reply`, `:send-failed`, `:unreachable`.

**A request that never returns.** Some servers don't refuse, they just never
answer; an HTTP read-timeout bounds one read, not the whole request. Every Blossom
request here is bounded from outside (`*blossom-timeout*`), and a fan-out bounds
each server separately, so one hung mirror can't strand the publish.

Neither a refusing relay nor a down mirror is an error — that's a normal publish —
so `nsite-publish` returns a **report** you can interrogate rather than a boolean:

```lisp
(multiple-value-bind (npub report)
    (cl-nostr.nsite:nsite-publish
     '("wss://relay.damus.io" "wss://nos.lol")           ; or an existing pool
     '("https://cdn.hzrd149.com" "https://blossom.primal.net")
     *kp*
     (list (cons "/index.html" "<!doctype html><p>hi")
           (cons "/" "<!doctype html><p>hi"))            ; same bytes: uploaded ONCE
     :title "my site")
  (cl-nostr.nsite:report-stored-p    report)   ; every blob reached >=1 server?
  (cl-nostr.nsite:report-published-p report)   ; >=1 relay accepted the manifest?
  (cl-nostr.nsite:report-problems    report)   ; => () when all is well
  npub)                                        ; => "npub1..." — the site's address
```

It also publishes the two discovery lists a gateway needs (**kind 10002** relays,
**kind 10063** Blossom servers), and it will *refuse* to publish a manifest naming
a blob that no server accepted — a manifest pointing at bytes nobody holds is how
a live site goes dark.

## Resolving needs only an npub and a path

The client half. No secret, nothing local:

```lisp
(let ((r (cl-nostr.nsite:nsite-resolve nil "npub1..." "/")))
  (cl-nostr.nsite:resolution-status       r)   ; :ok | :no-manifest | :no-path | :no-blob
  (cl-nostr.nsite:resolution-matched-path r)   ; "/index.html" — "/" is a directory
  (cl-nostr.nsite:resolution-bytes        r))  ; verified against the hash
```

`resolution-status` names the **first hop that broke**, which is the question worth
asking when a site looks stale: the npub published nothing, the site lacks that
path, or no mirror would hand over the blob. Bodies are checked against their
SHA-256 — the address *is* the hash — so a mirror serving the wrong bytes is a
failure, not a result. Legacy **kind 34128** per-path pointers are read as a
fallback when the kind-15128 manifest has no answer, because some gateways still
serve them and ignoring them would report "not found" for a path that is in fact
live; `resolution-source` says which format answered.

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
  pool                  multi-relay client: publish + subscribe + fetch + per-relay acks
  nip44/nip59/…         NIP-44 encryption, NIP-59 gift wrap, Double Ratchet
  blossom               Blossom BUD-01/02 blobs: bounded upload/download, fan-out
  nsite                 NIP-5A websites: publish (with a report) and resolve
  nip05                 NIP-05: name@domain -> pubkey
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
# === 81 passed, 0 failed ===
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
- sign/verify round-trips (incl. a tamper check) and filter matching;
- nsite manifest construction and path/hash tag round-trips, the gateway
  directory-index rule, and the partial-outcome reporting (a publish where one
  mirror timed out and one relay refused is a *success*; zero acceptances is not);
- **concurrent signing** — `secp256k1-fast` keeps mutable state across a scalar
  multiplication, so `cl-nostr.keys` serializes every call into it. Without that
  lock, 77 of 80 concurrent signatures signalled and the 3 that returned were
  silently *invalid* — which looks exactly like a bad key to a relay.

End to end, `bin/cl-nostr.lisp` connects to live relays and verifies the
signature of every note it streams.

## License

MIT.

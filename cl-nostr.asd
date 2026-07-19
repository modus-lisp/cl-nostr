;;;; cl-nostr.asd

(defsystem "cl-nostr"
  :description "A from-scratch Nostr client in Common Lisp — NIP-01 events
                (BIP340-signed), NIP-19 bech32 entities, and a WebSocket relay
                pool for publishing and subscribing."
  :version "0.1.0"
  :author "ynniv"
  :license "MIT"
  :depends-on ("secp256k1-fast"      ; BIP340 Schnorr + secp256k1 (event sigs + NIP-44 ECDH)
               "ironclad"            ; SHA-256 (event ids), HMAC/ChaCha20 (NIP-44), secure random
               "cl-base64"           ; NIP-44 payload base64
               "com.inuoe.jzon"      ; JSON: relay messages + events
               "websocket-driver"    ; WebSocket client (wss:// relays)
               "cl+ssl"              ; TLS for wss://
               "bordeaux-threads")   ; relay read loops + pool concurrency
  :serial t
  :components
  ((:module "src"
    :serial t
    :components
    ((:file "packages")   ; package + nickname layout
     (:file "util")       ; hex, utf-8, json helpers
     (:file "keys")       ; secret/public keys, Schnorr sign/verify (over secp256k1-fast)
     (:file "bech32")     ; NIP-19 bech32 entities (npub/nsec/note + TLV nprofile/nevent/naddr)
     (:file "event")      ; NIP-01 event: canonical serialization, id, sign, verify, JSON
     (:file "filter")     ; NIP-01 subscription filters
     (:file "relay")      ; one relay: websocket connect, REQ/EVENT/CLOSE, message dispatch
     (:file "pool")       ; high-level multi-relay client: publish + subscribe across relays
     (:file "nip44")      ; NIP-44 v2 payload encryption (ECDH -> HKDF -> ChaCha20 + HMAC)
     (:file "nip59")      ; NIP-59 gift wrap / NIP-17 private DMs (rumor -> seal -> wrap)
     (:file "double-ratchet")))) ; Nostr Double Ratchet (yakihonne "Secure DMs", kind-1060)
  :in-order-to ((test-op (test-op "cl-nostr/test"))))

(defsystem "cl-nostr/test"
  :depends-on ("cl-nostr")
  :components ((:module "inspect"
               :components ((:file "offline-test"))))
  :perform (test-op (o c) (uiop:symbol-call :cl-nostr.test :run)))

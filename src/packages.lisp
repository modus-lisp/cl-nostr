;;;; src/packages.lisp — package layout for cl-nostr.
;;;;
;;;; One package per concern, mirroring cl-consensus's `cl-consensus.*' scheme.
;;;; The crypto comes from the shared SECP256K1-FAST system (BIP340 Schnorr is
;;;; exactly Nostr's event-signature scheme — see secp256k1-fast/src/schnorr.lisp).

(defpackage #:cl-nostr.util
  (:use #:cl)
  (:export
   #:bytes->hex #:hex->bytes #:string->utf8 #:utf8->string
   #:sha256 #:random-bytes #:octets #:->bytes32))

(defpackage #:cl-nostr.keys
  (:use #:cl)
  (:local-nicknames (#:u #:cl-nostr.util)
                    (#:sch #:secp256k1-fast.schnorr))
  (:export
   #:keypair #:make-keypair #:generate-keypair #:keypair-from-secret
   #:keypair-secret-key #:keypair-public-key
   #:secret-hex #:public-hex #:public-key-of-secret
   #:sign #:verify))

(defpackage #:cl-nostr.bech32
  (:use #:cl)
  (:local-nicknames (#:u #:cl-nostr.util))
  (:export
   #:encode #:decode                     ; raw 5-bit bech32 (no length limit)
   #:npub-encode #:npub-decode
   #:nsec-encode #:nsec-decode
   #:note-encode #:note-decode
   #:nprofile-encode #:nprofile-decode
   #:nevent-encode #:nevent-decode
   #:naddr-encode #:naddr-decode
   #:decode-entity))                      ; dispatch on any nostr bech32 string

(defpackage #:cl-nostr.event
  (:use #:cl)
  (:local-nicknames (#:u #:cl-nostr.util)
                    (#:k #:cl-nostr.keys))
  (:export
   #:event #:make-event #:event-id #:event-pubkey #:event-created-at
   #:event-kind #:event-tags #:event-content #:event-sig
   #:build-event #:sign-event #:verify-event #:valid-event-p
   #:event->json #:json->event #:event->plist
   #:serialize-for-id #:compute-id
   #:tag-values #:first-tag-value #:e-tags #:p-tags
   ;; common kinds
   #:+kind-metadata+ #:+kind-text-note+ #:+kind-contacts+
   #:+kind-dm+ #:+kind-deletion+ #:+kind-reaction+))

(defpackage #:cl-nostr.filter
  (:use #:cl)
  (:local-nicknames (#:u #:cl-nostr.util))
  (:export
   #:filter #:make-filter #:filter->json #:filter-matches-p))

(defpackage #:cl-nostr.relay
  (:use #:cl)
  (:local-nicknames (#:u #:cl-nostr.util)
                    (#:ev #:cl-nostr.event)
                    (#:flt #:cl-nostr.filter))
  (:export
   #:relay #:connect-relay #:relay-url #:relay-connected-p #:close-relay
   #:publish #:subscribe #:unsubscribe
   #:on-event #:on-eose #:on-notice #:on-ok
   #:subscription #:subscription-id))

(defpackage #:cl-nostr.pool
  (:use #:cl)
  (:local-nicknames (#:u #:cl-nostr.util)
                    (#:ev #:cl-nostr.event)
                    (#:flt #:cl-nostr.filter)
                    (#:r #:cl-nostr.relay))
  (:export
   #:pool #:make-pool #:add-relay #:remove-relay #:close-pool
   #:pool-relays #:pool-publish #:pool-subscribe
   #:fetch-events #:fetch-one))

;;; A thin umbrella so REPL users get everything under one nickname.
(defpackage #:cl-nostr
  (:use #:cl)
  (:local-nicknames (#:util #:cl-nostr.util)
                    (#:keys #:cl-nostr.keys)
                    (#:bech32 #:cl-nostr.bech32)
                    (#:event #:cl-nostr.event)
                    (#:filter #:cl-nostr.filter)
                    (#:relay #:cl-nostr.relay)
                    (#:pool #:cl-nostr.pool)))

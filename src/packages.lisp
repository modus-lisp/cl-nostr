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
   #:relay #:connect-relay #:relay-url #:relay-connected-p #:close-relay #:relay-ping
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

;;; ---- encrypted messaging ------------------------------------------------
;;; NIP-44 v2 payload encryption, NIP-59 gift wrap (NIP-17 private DMs), and
;;; the Nostr Double Ratchet (yakihonne "Secure DMs").  Ported from the
;;; validated battle.crypto.* tree onto SECP256K1-FAST for the ECDH/Schnorr.

(defpackage #:cl-nostr.nip44
  (:use #:cl)
  (:local-nicknames (#:u #:cl-nostr.util)
                    (#:secp #:secp256k1-fast)
                    (#:sch #:secp256k1-fast.schnorr)
                    (#:ic #:ironclad)
                    (#:b64 #:cl-base64))
  (:export
   #:conversation-key #:nip44-encrypt #:nip44-decrypt
   #:nip44-encrypt-with-nonce #:nip44-encrypt-ck #:nip44-decrypt-ck
   #:calc-padded-len))

(defpackage #:cl-nostr.nip59
  (:use #:cl)
  (:local-nicknames (#:u #:cl-nostr.util)
                    (#:k #:cl-nostr.keys)
                    (#:ev #:cl-nostr.event)
                    (#:secp #:secp256k1-fast)
                    (#:sch #:secp256k1-fast.schnorr)
                    (#:nip44 #:cl-nostr.nip44)
                    (#:jzon #:com.inuoe.jzon))
  (:export
   #:build-giftwrap #:unwrap-giftwrap))

(defpackage #:cl-nostr.double-ratchet
  (:use #:cl)
  (:nicknames #:cl-nostr.dr)
  (:local-nicknames (#:u #:cl-nostr.util)
                    (#:secp #:secp256k1-fast)
                    (#:schnorr #:secp256k1-fast.schnorr)
                    (#:nip44 #:cl-nostr.nip44)
                    (#:ic #:ironclad)
                    (#:jzon #:com.inuoe.jzon))
  (:export
   #:dr-init #:dr-send-event #:dr-receive-event
   #:dr-session #:make-public-invite #:decrypt-invite-response
   #:session-from-invite-response #:dr-state->json #:json->dr-state
   #:gen-priv #:priv->pub-hex #:ck #:kdf
   #:*message-kind* #:*invite-kind* #:*invite-response-kind* #:*chat-kind*
   #:dr-our-current-pub #:dr-their-next-pub #:dr-their-current-pub
   #:dr-can-send-p))

;;; ---- publishing: Blossom blobs + nsite static sites --------------------
;;; Blossom (BUD-01/02) stores content-addressed blobs behind a kind-24242
;;; Nostr auth event; nsite maps site paths to those blobs with kind-34128
;;; parameterized-replaceable events.  Together they publish a website to Nostr.

(defpackage #:cl-nostr.blossom
  (:use #:cl)
  (:local-nicknames (#:u #:cl-nostr.util)
                    (#:k #:cl-nostr.keys)
                    (#:ev #:cl-nostr.event)
                    (#:b64 #:cl-base64)
                    (#:jzon #:com.inuoe.jzon))
  (:export
   #:blossom-upload #:blossom-url))

(defpackage #:cl-nostr.nsite
  (:use #:cl)
  (:local-nicknames (#:u #:cl-nostr.util)
                    (#:k #:cl-nostr.keys)
                    (#:b #:cl-nostr.bech32)
                    (#:ev #:cl-nostr.event)
                    (#:pool #:cl-nostr.pool)
                    (#:blossom #:cl-nostr.blossom))
  (:export
   #:nsite-put #:nsite-publish #:nsite-manifest))

(defpackage #:cl-nostr.nip05
  (:use #:cl)
  (:local-nicknames (#:u #:cl-nostr.util)
                    (#:jzon #:com.inuoe.jzon))
  (:export
   #:resolve #:resolve-pubkey #:nip05-address-p))

;;; A thin umbrella so REPL users get everything under one nickname.
(defpackage #:cl-nostr
  (:use #:cl)
  (:local-nicknames (#:util #:cl-nostr.util)
                    (#:keys #:cl-nostr.keys)
                    (#:bech32 #:cl-nostr.bech32)
                    (#:event #:cl-nostr.event)
                    (#:filter #:cl-nostr.filter)
                    (#:relay #:cl-nostr.relay)
                    (#:pool #:cl-nostr.pool)
                    (#:nip44 #:cl-nostr.nip44)
                    (#:nip59 #:cl-nostr.nip59)
                    (#:double-ratchet #:cl-nostr.double-ratchet)
                    (#:blossom #:cl-nostr.blossom)
                    (#:nsite #:cl-nostr.nsite)))

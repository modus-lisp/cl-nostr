;;;; src/packages.lisp — package layout for cl-nostr.
;;;;
;;;; One package per concern, mirroring cl-consensus's `cl-consensus.*' scheme.
;;;; The crypto comes from the shared SECP256K1-FAST system (BIP340 Schnorr is
;;;; exactly Nostr's event-signature scheme — see secp256k1-fast/src/schnorr.lisp).

(defpackage #:cl-nostr.util
  (:use #:cl)
  (:local-nicknames (#:bt #:bordeaux-threads))
  (:export
   #:bytes->hex #:hex->bytes #:string->utf8 #:utf8->string
   #:sha256 #:random-bytes #:octets #:->bytes32
   ;; bounded work: nothing in a network client may be unbounded
   #:call-with-deadline #:with-deadline #:call-in-parallel
   ;; waiting while something else delivers: a sleep, or a pump (see WAIT-STEP)
   #:wait-step))

(defpackage #:cl-nostr.keys
  (:use #:cl)
  (:local-nicknames (#:u #:cl-nostr.util)
                    (#:bt #:bordeaux-threads)
                    (#:sch #:secp256k1-fast.schnorr))
  (:export
   #:*curve-lock*
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
   #:decode-entity                       ; dispatch on any nostr bech32 string
   #:pubkey-hex))                        ; npub / nprofile / hex -> hex

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
   #:pump #:*pump-hooks*
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
   #:pool #:pool-p #:make-pool #:add-relay #:remove-relay #:close-pool
   #:pool-relays #:pool-relay-urls #:pool-unreachable
   #:pool-publish #:pool-publish-sync #:pool-subscribe
   #:fetch-events #:fetch-one
   ;; per-relay publish outcomes: a partial result is the normal result
   #:relay-ack #:ack-url #:ack-event-id #:ack-status #:ack-message
   #:ack-accepted-p #:ack-replied-p #:acks-accepted))

;;; ---- encrypted messaging ------------------------------------------------
;;; NIP-44 v2 payload encryption, NIP-59 gift wrap (NIP-17 private DMs), and
;;; the Nostr Double Ratchet (yakihonne "Secure DMs").  All three sit on
;;; SECP256K1-FAST for the ECDH/Schnorr.

(defpackage #:cl-nostr.nip44
  (:use #:cl)
  (:local-nicknames (#:u #:cl-nostr.util)
                    (#:secp #:secp256k1-fast)
                    (#:sch #:secp256k1-fast.schnorr)
                    (#:na #:natrium)
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
                    (#:json #:json-simple))
  (:export
   #:build-giftwrap #:unwrap-giftwrap
   #:wrap-rumor #:unwrap-rumor))

(defpackage #:cl-nostr.double-ratchet
  (:use #:cl)
  (:nicknames #:cl-nostr.dr)
  (:local-nicknames (#:u #:cl-nostr.util)
                    (#:secp #:secp256k1-fast)
                    (#:schnorr #:secp256k1-fast.schnorr)
                    (#:nip44 #:cl-nostr.nip44)
                    (#:na #:natrium)
                    (#:json #:json-simple))
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
;;; Nostr auth event; nsite maps site paths to those blobs with a kind-15128
;;; root manifest (NIP-5A).  Together they publish a website to Nostr, and
;;; NSITE-RESOLVE reads one back from nothing but an npub and a path.

(defpackage #:cl-nostr.blossom
  (:use #:cl)
  (:local-nicknames (#:u #:cl-nostr.util)
                    (#:k #:cl-nostr.keys)
                    (#:ev #:cl-nostr.event)
                    (#:b64 #:cl-base64)
                    (#:json #:json-simple))
  (:export
   #:*blossom-timeout*
   #:blossom-url #:blossom-upload #:blossom-upload-all
   #:blossom-fetch #:blossom-download #:blossom-download-any
   #:blossom-error #:blossom-error-server #:blossom-error-hash
   #:blossom-error-status #:blossom-error-detail
   ;; per-server outcomes
   #:blob-upload #:upload-server #:upload-hash #:upload-ok-p #:upload-url
   #:upload-descriptor #:upload-error #:upload-seconds
   #:blob-fetch #:fetch-source #:fetch-expected #:fetch-ok-p #:fetch-status
   #:fetch-sha256 #:fetch-bytes #:fetch-error #:fetch-seconds))

(defpackage #:cl-nostr.nsite
  (:use #:cl)
  (:local-nicknames (#:u #:cl-nostr.util)
                    (#:k #:cl-nostr.keys)
                    (#:b #:cl-nostr.bech32)
                    (#:ev #:cl-nostr.event)
                    (#:flt #:cl-nostr.filter)
                    (#:pool #:cl-nostr.pool)
                    (#:blossom #:cl-nostr.blossom))
  (:export
   #:+kind-nsite-root+ #:+kind-nsite-legacy+ #:+kind-relay-list+ #:+kind-server-list+
   #:*discovery-relays* #:*gateway* #:*content-types*
   ;; the manifest, as data
   #:nsite-manifest #:manifest-paths #:manifest-servers #:manifest-lookup
   #:manifest-title #:manifest-description
   #:relay-list-event #:server-list-event #:legacy-pointer
   ;; publish, and what every server and relay did with it
   #:nsite-publish #:nsite-put
   #:nsite-report #:report-npub #:report-pubkey #:report-paths #:report-uploads
   #:report-publications #:report-publication #:report-manifest #:report-blob-uploads
   #:report-stored-p #:report-published-p #:report-problems #:report-ok-p
   #:publication #:publication-event #:publication-acks #:publication-kind
   #:publication-accepted
   ;; resolve: the client half — an npub and a path is enough
   #:nsite-resolve #:nsite-resolution #:resolution-npub #:resolution-pubkey
   #:resolution-path #:resolution-matched-path #:resolution-hash #:resolution-source
   #:resolution-manifest #:resolution-servers #:resolution-fetches #:resolution-server
   #:resolution-bytes #:resolution-status #:resolution-ok-p
   #:nsite-fetch-manifest #:nsite-fetch-manifests #:nsite-fetch-legacy
   #:nsite-relays #:nsite-servers
   #:nsite-gateway-url #:nsite-gateway-fetch))

(defpackage #:cl-nostr.nip05
  (:use #:cl)
  (:local-nicknames (#:u #:cl-nostr.util)
                    (#:json #:json-simple))
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

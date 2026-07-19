;;;; src/nip59.lisp — NIP-59 gift wrap (the envelope under NIP-17 private DMs).
;;;;
;;;; A message is delivered as three nested layers:
;;;;
;;;;   rumor (kind 14, UNSIGNED)  the real message + real timestamp
;;;;     -> seal (kind 13)        rumor NIP-44-encrypted to the recipient,
;;;;                              signed by the SENDER, timestamp backdated
;;;;     -> gift wrap (kind 1059) seal NIP-44-encrypted to the recipient,
;;;;                              signed by a THROWAWAY ephemeral key
;;;;
;;;; Only the recipient can peel the wrap; the outer 1059 exposes neither the
;;;; sender nor the content.  Ported from siteglass.notify's build/unwrap
;;;; giftwrap — the siteglass-specific parts (relays, publish, identity, DM-bot)
;;;; are left behind; publishing is cl-nostr's own pool-publish / pool-subscribe.
;;;;
;;;; The sender/ephemeral keys sign via cl-nostr.event:build-event (BIP340 over
;;;; SECP256K1-FAST), and NIP-44 v2 provides the encryption.  build-giftwrap
;;;; returns a cl-nostr EVENT (kind 1059) ready for pool-publish; unwrap-giftwrap
;;;; takes such an EVENT back apart.

(in-package #:cl-nostr.nip59)

(defconstant +unix-epoch+ 2208988800)
(defun unix-now () (- (get-universal-time) +unix-epoch+))

(defun random-past-ts (&optional (max 172800))
  "A timestamp jittered up to MAX seconds (default ~2 days) into the past — the
seal is backdated for timing privacy; the rumor still carries the real time."
  (- (unix-now) (random max)))

(defun %sec->int (sec)
  "Coerce a secret key given as an integer, hex string, byte vector, or a
cl-nostr KEYPAIR to the integer scalar used for signing / ECDH."
  (etypecase sec
    (integer sec)
    (k:keypair (secp:bytes-to-int (k:keypair-secret-key sec)))
    (string (secp:bytes-to-int (u:hex->bytes sec)))
    (sequence (secp:bytes-to-int (coerce sec '(vector (unsigned-byte 8)))))))

(defun %kp-from-int (sec-int)
  (k:keypair-from-secret (secp:int-to-bytes32 sec-int)))

(defun %pub-hex (sec-int)
  (u:bytes->hex (sch:pubkey-xonly sec-int)))

(defun %tags->vec (tags)
  "cl-nostr tags (list of lists of strings) -> the vector-of-vectors JSON shape."
  (coerce (mapcar (lambda (tg) (coerce tg 'vector)) tags) 'vector))

(defun %rumor-json (pubkey created kind tags content)
  "Serialize an UNSIGNED rumor event (kind 14): id + pubkey + created_at + kind +
tags + content, no signature.  The id is computed with cl-nostr's canonical
NIP-01 serializer so it matches what any client would compute."
  (let* ((id (ev:compute-id pubkey created kind tags content))
         (h (make-hash-table :test 'equal)))
    (setf (gethash "id" h) id
          (gethash "pubkey" h) pubkey
          (gethash "created_at" h) created
          (gethash "kind" h) kind
          (gethash "tags" h) (%tags->vec tags)
          (gethash "content" h) content)
    (with-output-to-string (s) (jzon:stringify h :stream s))))

(defun build-giftwrap (sender-sec recipient-hex message)
  "NIP-59: wrap MESSAGE for RECIPIENT-HEX (x-only pubkey hex) from SENDER-SEC
(integer / hex / bytes / keypair).  Builds rumor(14) -> seal(13, by sender) ->
gift wrap(1059, by an ephemeral key) and returns the kind-1059 cl-nostr EVENT
to hand to pool-publish."
  (let* ((sender-int (%sec->int sender-sec))
         (sender-kp (%kp-from-int sender-int))
         (sender-pub (k:public-hex sender-kp))
         (now (unix-now))
         ;; rumor: the real message, unsigned, real timestamp
         (rumor-json (%rumor-json sender-pub now 14
                                  (list (list "p" recipient-hex)) message))
         ;; seal: rumor encrypted to recipient, signed by sender, backdated
         (seal-content (nip44:nip44-encrypt sender-int recipient-hex rumor-json))
         (seal-ev (ev:build-event sender-kp 13 seal-content
                                  :tags '() :created-at (random-past-ts)))
         (seal-json (ev:event->json seal-ev))
         ;; wrap: seal encrypted to recipient, signed by a throwaway key.
         ;; created_at stays ~now so relays/clients filtering `since:` fetch it.
         (eph-int (secp:bytes-to-int (u:random-bytes 32)))
         (eph-kp (%kp-from-int eph-int))
         (wrap-content (nip44:nip44-encrypt eph-int recipient-hex seal-json)))
    (ev:build-event eph-kp 1059 wrap-content
                    :tags (list (list "p" recipient-hex)) :created-at now)))

(defun unwrap-giftwrap (recipient-sec wrap-event)
  "Recipient side: 1059 -> seal -> rumor.  WRAP-EVENT is a cl-nostr EVENT (as
delivered by pool-subscribe); RECIPIENT-SEC is our secret (int/hex/bytes/keypair).
Returns (values plaintext sender-pubkey-hex created_at)."
  (let* ((sec (%sec->int recipient-sec))
         (seal (jzon:parse (nip44:nip44-decrypt sec (ev:event-pubkey wrap-event)
                                                (ev:event-content wrap-event))))
         (rumor (jzon:parse (nip44:nip44-decrypt sec (gethash "pubkey" seal)
                                                 (gethash "content" seal)))))
    (values (gethash "content" rumor)
            (gethash "pubkey" rumor)
            (truncate (gethash "created_at" rumor)))))

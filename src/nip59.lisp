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
;;;; sender nor the content.  Publishing is cl-nostr's own pool-publish /
;;;; pool-subscribe.
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

(defun %sender-keypair (sec)
  "SEC as a KEYPAIR: a keypair as-is, or a fixed 32-byte secret (whose keypair shares
its buffer).  Integers, hex and heap bytes are refused -- import them once with
KEYPAIR-FROM-SECRET."
  (if (k:keypair-p sec)
      sec
      (let ((sk (k:secret-key-of sec)))       ; borrows SEC's buffer: never wipe this keypair
        (k::%make-keypair sk (k:public-key-of-secret sk)))))

(defun %pub-hex (sec) (u:bytes->hex (k:public-key-of-secret (k:secret-key-of sec))))

(defmacro %with-ephemeral ((kp) &body body)
  "Bind KP to a throwaway keypair (secret generated in fixed memory), wiped on exit."
  `(let ((,kp (k:generate-keypair)))
     (unwind-protect (progn ,@body) (k:keypair-wipe ,kp))))

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
    (with-output-to-string (s) (json:stringify h :stream s))))

(defun build-giftwrap (sender-sec recipient-hex message &key after)
  "NIP-59: wrap MESSAGE for RECIPIENT-HEX (x-only pubkey hex) from SENDER-SEC
(a keypair, or a fixed 32-byte secret).  Builds rumor(14) -> seal(13, by sender) ->
gift wrap(1059, by an ephemeral key) and returns the kind-1059 cl-nostr EVENT
to hand to pool-publish.

AFTER is the created_at of the message this one answers.  A reply is stamped
strictly later, so a conversation still reads in order when the two ends
disagree about the time: unlike a chat server, nobody here holds an
authoritative clock, and a reply generated within the same second as the
question — or on a box whose clock trails the phone's by a little — otherwise
sorts ABOVE the question in the recipient's client.  Seconds are the whole
resolution Nostr offers, so this is not an edge case; it is most fast replies."
  (let* ((sender-kp (%sender-keypair sender-sec))
         (sender-pub (k:public-hex sender-kp))
         (now (if after (max (unix-now) (1+ after)) (unix-now)))
         ;; rumor: the real message, unsigned, real timestamp
         (rumor-json (%rumor-json sender-pub now 14
                                  (list (list "p" recipient-hex)) message))
         ;; seal: rumor encrypted to recipient, signed by sender, backdated
         (seal-content (nip44:nip44-encrypt sender-kp recipient-hex rumor-json))
         (seal-ev (ev:build-event sender-kp 13 seal-content
                                  :tags '() :created-at (random-past-ts)))
         (seal-json (ev:event->json seal-ev)))
    ;; wrap: seal encrypted to recipient, signed by a throwaway key (wiped after).
    ;; created_at stays ~now so relays/clients filtering `since:` fetch it.
    (%with-ephemeral (eph-kp)
      (ev:build-event eph-kp 1059 (nip44:nip44-encrypt eph-kp recipient-hex seal-json)
                      :tags (list (list "p" recipient-hex)) :created-at now))))

(defun unwrap-giftwrap (recipient-sec wrap-event &key (verify t))
  "Recipient side: 1059 -> seal -> rumor.  WRAP-EVENT is a cl-nostr EVENT (as
delivered by pool-subscribe); RECIPIENT-SEC is our secret (a keypair or fixed secret).
Returns (values plaintext sender-pubkey-hex created_at), where SENDER-PUBKEY-HEX is
the AUTHENTICATED sender: the key that signed the seal.

When VERIFY (the default), the seal's signature is checked and the rumor's pubkey MUST
equal the seal's signer — otherwise the sender is forgeable (an attacker seals, with
their own key, a rumor whose pubkey names someone else, and a naive reader trusts the
rumor's claim).  A failure signals an error (fail closed).  Pass :VERIFY NIL only when
the caller does its own checking."
  (let* ((sec (%sender-keypair recipient-sec))
         (seal-json (nip44:nip44-decrypt sec (ev:event-pubkey wrap-event)
                                         (ev:event-content wrap-event)))
         (seal (ev:json->event seal-json))
         (seal-pub (ev:event-pubkey seal))
         (rumor (json:parse (nip44:nip44-decrypt sec seal-pub (ev:event-content seal))))
         (rumor-pub (gethash "pubkey" rumor)))
    (when verify
      (unless (ev:verify-event seal)
        (error "gift wrap: seal signature invalid — forged/altered sender ~a" seal-pub))
      (unless (and (stringp rumor-pub) (string= rumor-pub seal-pub))
        (error "gift wrap: rumor pubkey ~a is not the seal's signer ~a — unbound rumor"
               rumor-pub seal-pub)))
    (values (gethash "content" rumor)
            seal-pub                                  ; the AUTHENTICATED sender
            (truncate (or (gethash "created_at" rumor) 0)))))

;;; ---- general rumors -------------------------------------------------------
;;;
;;; BUILD-GIFTWRAP / UNWRAP-GIFTWRAP above are NIP-17 direct messages: the rumor
;;; is always kind 14 and only its content comes back.  Protocols that carry
;;; their own rumor kinds over NIP-59 (Marmot's kind-444 Welcome, for one) need
;;; to choose the rumor's kind, tags and created_at, and need the whole rumor
;;; back — its kind and tags are part of what the receiver must validate.

(defun wrap-rumor (sender-sec recipient-hex kind content &key tags created-at)
  "NIP-59: wrap an unsigned rumor of KIND / TAGS / CONTENT, authored by
SENDER-SEC, for RECIPIENT-HEX.  The seal is backdated as in BUILD-GIFTWRAP; the
rumor keeps CREATED-AT (default now).  Returns the kind-1059 EVENT."
  (let* ((sender-kp (%sender-keypair sender-sec))
         (sender-pub (k:public-hex sender-kp))
         (now (unix-now))
         (rumor-json (%rumor-json sender-pub (or created-at now) kind tags content))
         (seal-ev (ev:build-event sender-kp 13 (nip44:nip44-encrypt sender-kp recipient-hex rumor-json)
                                  :tags '() :created-at (random-past-ts))))
    (%with-ephemeral (eph-kp)
      (ev:build-event eph-kp 1059 (nip44:nip44-encrypt eph-kp recipient-hex (ev:event->json seal-ev))
                      :tags (list (list "p" recipient-hex)) :created-at now))))

(defun unwrap-rumor (recipient-sec wrap-event)
  "Open a kind-1059 WRAP-EVENT addressed to RECIPIENT-SEC.  Returns (values
RUMOR SEAL): RUMOR is an unsigned EVENT (id set, no sig).  Fails closed unless
the wrap verifies and has exactly one p tag naming us, the seal is a verified
kind 13, the rumor's pubkey is the seal's signer, and the rumor id matches its
contents."
  (let* ((sec (%sender-keypair recipient-sec))
         (me (k:public-hex sec)))
    (unless (and (= (ev:event-kind wrap-event) 1059) (ev:verify-event wrap-event))
      (error "gift wrap: not a valid kind-1059 event"))
    (let ((ps (ev:tag-values wrap-event "p")))
      (unless (and (= (length ps) 1) (string= (first ps) me))
        (error "gift wrap: not addressed to ~a" me)))
    (let* ((seal (ev:json->event (nip44:nip44-decrypt sec (ev:event-pubkey wrap-event)
                                                      (ev:event-content wrap-event))))
           (seal-pub (ev:event-pubkey seal)))
      (unless (and (= (ev:event-kind seal) 13) (ev:verify-event seal))
        (error "gift wrap: seal is not a valid kind-13 event"))
      (let* ((ht (json:parse (nip44:nip44-decrypt sec seal-pub (ev:event-content seal))))
             (rumor (ev:json->event ht)))
        (when (nth-value 1 (gethash "sig" ht))
          (error "gift wrap: rumor carries a signature"))
        (unless (and (stringp (ev:event-pubkey rumor)) (string= (ev:event-pubkey rumor) seal-pub))
          (error "gift wrap: rumor pubkey ~a is not the seal's signer ~a" (ev:event-pubkey rumor) seal-pub))
        (unless (and (stringp (ev:event-id rumor))
                     (string= (ev:event-id rumor)
                              (ev:compute-id (ev:event-pubkey rumor) (ev:event-created-at rumor)
                                             (ev:event-kind rumor) (ev:event-tags rumor)
                                             (ev:event-content rumor))))
          (error "gift wrap: rumor id does not match its contents"))
        (values rumor seal)))))

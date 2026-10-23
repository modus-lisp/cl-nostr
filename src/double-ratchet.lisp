;;;; src/double-ratchet.lisp — the Nostr Double Ratchet ("Secure DMs").
;;;;
;;;; Native Lisp port of the Nostr "Double Ratchet with header encryption"
;;;; (Signal-style), the scheme behind yakihonne's "Secure DMs" and the NIP-118
;;;; invite handshake.  Wire-compatible with the reference implementation
;;;; `nostr-double-ratchet` (mmalmi / iris).
;;;;
;;;; Validated cross-implementation against the reference acting as the peer.
;;;; The crypto backend is cl-nostr's own stack: SECP256K1-FAST for ECDH/Schnorr
;;;; and cl-nostr.nip44 for the v2 payloads.
;;;;
;;;; Crypto facts pinned from the reference source:
;;;;   kdf(in1,in2,n): prk = HMAC-SHA256(key=in2, msg=in1);
;;;;                   out_i = HMAC-SHA256(prk, [i,1])   (i = 1..n, 32 bytes each)
;;;;   conversation key = nip44 getConversationKey(priv, pubhex)
;;;;   header / message payloads = nip44.encrypt(plaintext, key)
;;;;   outer message event: kind 1060, signed by the ephemeral ratchet key,
;;;;     tags [["header", <nip44(header, DH(ourCur, theirNext))>]],
;;;;     content = <nip44(rumorJSON, messageKey)>
;;;;   invite event: kind 30078, tags ephemeralKey/sharedSecret/d/l
;;;;   invite response: kind 1059 (two-layer: random->ephemeral envelope,
;;;;     shared-secret + DH(identity) inner)

(in-package #:cl-nostr.double-ratchet)

(defparameter *message-kind* 1060)
(defparameter *invite-kind* 30078)
(defparameter *invite-response-kind* 1059)
(defparameter *chat-kind* 14)
(defparameter *max-skip* 1000)

;;; ------------------------- byte / hex / key utils -------------------------

(defun u8 (n) (make-array n :element-type '(unsigned-byte 8)))
(defun cat (&rest vs) (apply #'concatenate '(vector (unsigned-byte 8)) vs))
(defun hex->bytes (h) (u:hex->bytes h))
(defun bytes->hex (b) (u:bytes->hex b))
(defun utf8 (s) (u:string->utf8 s))

;;; Owned secret buffers.
(defun %new-secret () (gossamer:acquire :octets 32))
(defun %free (b) (when b (gossamer:release :octets 32 b)) nil)
(defun %own-copy (b) (and b (replace (%new-secret) b)))
(defun %own-from-hex (h)
  (and h (let ((b (hex->bytes h))) (prog1 (%own-copy b) (fill b 0)))))

(defun gen-priv ()
  "A fresh random secp256k1 secret key: a 32-byte fixed buffer, owned by the caller
(release it with DR-FREE-KEY when it is not handed to a session)."
  (let ((b (%new-secret)))
    (loop (natrium:random-bytes-into b)
          (when (ignore-errors (schnorr:pubkey-xonly b)) (return b)))))

(defun dr-free-key (b) "Wipe and release a key from GEN-PRIV or MAKE-PUBLIC-INVITE." (%free b))

(defun %secret (priv)
  "PRIV as a fixed 32-byte secret: a cl-nostr keypair or a fixed buffer."
  (cl-nostr.keys:secret-key-of priv))

(defun priv->pub-hex (priv)
  "x-only schnorr public key, lowercase hex (nostr getPublicKey)."
  (bytes->hex (schnorr:pubkey-xonly (%secret priv))))

(defmacro with-ck ((var priv pub-hex) &body body)
  "Bind VAR to the NIP-44 conversation key between PRIV and PUB-HEX, in fixed scratch."
  `(gossamer:with-fixed-scratch ((,var :octets 32))
     (nip44::%conversation-key-into (%secret ,priv) (hex->bytes ,pub-hex) ,var)
     ,@body))

(defun ck (priv pub-hex)
  "NIP-44 conversation key between our PRIV and their PUB-HEX (x-only), as a fresh
owned fixed buffer (release with DR-FREE-KEY)."
  (with-ck (c priv pub-hex) (%own-copy c)))

(defparameter +chain-step+
  (make-array 1 :element-type '(unsigned-byte 8) :initial-element 1)
  "The single-byte [1] info used to ratchet a symmetric chain key forward.")

(defun kdf-into (in1 in2 &rest outs)
  "HKDF-SHA256 as the reference uses it: prk = HMAC(key=in2, msg=in1), then
OUT_i = HMAC(prk, [i,1]) into each fixed buffer of OUTS.  IN1 may be one of OUTS: the
PRK is computed before anything is written."
  (gossamer:with-fixed-scratch ((prk :octets 32) (info :octets 2))
    (na:hmac-sha256-into in2 in1 prk)
    (loop for out in outs for i from 1
          do (setf (aref info 0) i (aref info 1) 1)
             (na:hmac-sha256-into prk info out))
    (values-list outs)))

(defun kdf (in1 in2 n)
  "KDF-INTO with N fresh owned fixed outputs, returned as a list."
  (let ((outs (loop repeat n collect (%new-secret))))
    (apply #'kdf-into in1 in2 outs)
    outs))

;;; ------------------------------ JSON helpers ------------------------------

(defun jstr (obj) (with-output-to-string (s) (json:stringify obj :stream s)))

(defun ht (&rest kvs)
  (let ((h (make-hash-table :test 'equal)))
    (loop for (k v) on kvs by #'cddr do (setf (gethash k h) v))
    h))

(defun jget (parsed key) (and (hash-table-p parsed) (gethash key parsed)))

;;; --------------------------- event id + signing ---------------------------

(defun event-id-hex (pub created kind tags content)
  (let ((ser (jstr (vector 0 pub created kind tags content))))
    (bytes->hex (u:sha256 (utf8 ser)))))

(defun sign-event (priv pub-hex created kind tags content)
  "Build a signed Nostr event hash-table (NIP-01), signed by PRIV (keypair or fixed)."
  (let* ((id (event-id-hex pub-hex created kind tags content))
         (aux (u8 32)))
    (natrium:random-bytes-into aux)
    (ht "id" id "pubkey" pub-hex "created_at" created "kind" kind
        "tags" tags "content" content
        "sig" (bytes->hex (schnorr:schnorr-sign (%secret priv) (hex->bytes id) aux)))))

(defun unix-now () (- (get-universal-time) (encode-universal-time 0 0 0 1 1 1970 0)))

;;; --------------------------------- state ----------------------------------

(defstruct (dr-session (:conc-name dr-))
  root-key                ; owned fixed buffer
  their-current-pub       ; hex | nil
  their-next-pub          ; hex
  our-current-priv our-current-pub  ; owned fixed buffer | nil / hex | nil
  our-next-priv our-next-pub        ; owned fixed buffer / hex
  recv-chain send-chain   ; owned fixed buffers | nil
  (send-n 0) (recv-n 0) (prev-send-n 0)
  skipped)                ; equal hashtable: sender-hex -> (cons header-keys msgkeys-ht), all owned

(defun %set-key (s accessor-setter old new)
  (declare (ignore s accessor-setter))
  (%free old) new)

(defun dr-can-send-p (s)
  (and (dr-their-next-pub s) (dr-our-current-priv s) t))

(defun dr-init (their-eph-pub our-eph-priv is-initiator shared-secret-bytes)
  "Initialise a session.  IS-INITIATOR = the one who sends first (invitee/accept
side).  The responder (our bot) starts with no sending chain and must receive a
message before it can reply.  OUR-EPH-PRIV (a keypair or fixed secret) and
SHARED-SECRET-BYTES are COPIED: the caller keeps ownership of its own."
  (let ((ours (%own-copy (%secret our-eph-priv))))
    (if is-initiator
        (let* ((our-next-priv (gen-priv))
               (root (%new-secret)) (send (%new-secret)))
          (with-ck (c our-next-priv their-eph-pub)
            (kdf-into shared-secret-bytes c root send))
          (make-dr-session
           :root-key root
           :their-next-pub their-eph-pub
           :our-current-priv ours :our-current-pub (priv->pub-hex ours)
           :our-next-priv our-next-priv :our-next-pub (priv->pub-hex our-next-priv)
           :send-chain send
           :skipped (make-hash-table :test 'equal)))
        (make-dr-session
         :root-key (%own-copy shared-secret-bytes)
         :their-next-pub their-eph-pub
         :our-current-priv nil :our-current-pub nil
         :our-next-priv ours :our-next-pub (priv->pub-hex ours)
         :send-chain nil
         :skipped (make-hash-table :test 'equal)))))

(defun %free-skipped (skipped)
  (maphash (lambda (k entry)
             (declare (ignore k))
             (mapc #'%free (car entry))
             (maphash (lambda (n mk) (declare (ignore n)) (%free mk)) (cdr entry)))
           skipped))

(defun dr-free (s)
  "Wipe and release every key S owns.  S is unusable afterwards."
  (%free (dr-root-key s)) (%free (dr-recv-chain s)) (%free (dr-send-chain s))
  (%free (dr-our-current-priv s)) (%free (dr-our-next-priv s))
  (when (dr-skipped s) (%free-skipped (dr-skipped s)))
  (setf (dr-root-key s) nil (dr-recv-chain s) nil (dr-send-chain s) nil
        (dr-our-current-priv s) nil (dr-our-next-priv s) nil (dr-skipped s) nil)
  s)

;;; ------------------------------- ratchet ----------------------------------

(defun ratchet-encrypt (s plaintext)
  "Returns (values header-hashtable ciphertext-string)."
  (gossamer:with-fixed-scratch ((mk :octets 32))
    (kdf-into (dr-send-chain s) +chain-step+ (dr-send-chain s) mk)
    (let ((header (ht "number" (dr-send-n s)
                      "nextPublicKey" (dr-our-next-pub s)
                      "previousChainLength" (dr-prev-send-n s))))
      (incf (dr-send-n s))
      (values header (nip44:nip44-encrypt-ck plaintext mk)))))

(defun ratchet-decrypt (s header ciphertext sender)
  (let ((skipped-pt (try-skipped-message-keys s header ciphertext sender)))
    (or skipped-pt
        (progn
          (skip-message-keys s (jget header "number") sender)
          (gossamer:with-fixed-scratch ((mk :octets 32))
            (kdf-into (dr-recv-chain s) +chain-step+ (dr-recv-chain s) mk)
            (incf (dr-recv-n s))
            (nip44:nip44-decrypt-ck ciphertext mk))))))

(defun ratchet-step (s)
  (setf (dr-prev-send-n s) (dr-send-n s)
        (dr-send-n s) 0
        (dr-recv-n s) 0)
  (gossamer:with-fixed-scratch ((root1 :octets 32))
    (unless (dr-recv-chain s) (setf (dr-recv-chain s) (%new-secret)))
    (with-ck (c (dr-our-next-priv s) (dr-their-next-pub s))
      (kdf-into (dr-root-key s) c root1 (dr-recv-chain s)))
    (%free (dr-our-current-priv s))
    (setf (dr-our-current-priv s) (dr-our-next-priv s)
          (dr-our-current-pub s)  (dr-our-next-pub s))
    (let ((next (gen-priv)))
      (setf (dr-our-next-priv s) next
            (dr-our-next-pub s)  (priv->pub-hex next)))
    (unless (dr-send-chain s) (setf (dr-send-chain s) (%new-secret)))
    (with-ck (c (dr-our-next-priv s) (dr-their-next-pub s))
      (kdf-into root1 c (dr-root-key s) (dr-send-chain s)))))

;;; --------------------------- skipped message keys --------------------------

(defun ensure-skip-entry (s sender)
  (or (gethash sender (dr-skipped s))
      (setf (gethash sender (dr-skipped s))
            (cons '() (make-hash-table :test 'eql)))))   ; (header-keys . msgkeys-ht)

(defun %remember-header-key (entry priv sender)
  (let ((k (ck priv sender)))
    (if (member k (car entry) :test #'equalp) (%free k) (push k (car entry)))))

(defun skip-message-keys (s until sender)
  (when (<= until (dr-recv-n s)) (return-from skip-message-keys))
  (when (> until (+ (dr-recv-n s) *max-skip*))
    (error "double-ratchet: too many skipped messages"))
  (let ((fresh (not (gethash sender (dr-skipped s)))))
    (let ((entry (ensure-skip-entry s sender)))
      (when fresh
        ;; cache the header keys for this sender (current + next)
        (when (dr-our-current-priv s) (%remember-header-key entry (dr-our-current-priv s) sender))
        (%remember-header-key entry (dr-our-next-priv s) sender))
      (loop while (< (dr-recv-n s) until) do
        (let ((mk (%new-secret)))
          (kdf-into (dr-recv-chain s) +chain-step+ (dr-recv-chain s) mk)
          (%free (gethash (dr-recv-n s) (cdr entry)))
          (setf (gethash (dr-recv-n s) (cdr entry)) mk)
          (incf (dr-recv-n s)))))))

(defun try-skipped-message-keys (s header ciphertext sender)
  (let ((entry (gethash sender (dr-skipped s))))
    (when entry
      (let ((mk (gethash (jget header "number") (cdr entry))))
        (when mk
          (remhash (jget header "number") (cdr entry))
          (unwind-protect (nip44:nip44-decrypt-ck ciphertext mk)
            (%free mk)
            (when (zerop (hash-table-count (cdr entry)))
              (mapc #'%free (car entry))
              (remhash sender (dr-skipped s)))))))))

;;; ------------------------------ header decrypt ----------------------------

(defun try-dec-header (enc-header conv-key)
  "Returns the parsed header hashtable or NIL on failure."
  (handler-case (json:parse (nip44:nip44-decrypt-ck enc-header conv-key))
    (error () nil)))

(defun decrypt-header (s event-pubkey enc-header)
  "Returns (values header should-ratchet is-skipped). Signals on total failure."
  ;; 1) ourCurrent key
  (when (and (dr-our-current-priv s)
             (or (null (dr-their-current-pub s))
                 (string= event-pubkey (dr-their-current-pub s))
                 (string= event-pubkey (dr-their-next-pub s))))
    (let ((h (with-ck (c (dr-our-current-priv s) event-pubkey) (try-dec-header enc-header c))))
      (when h (return-from decrypt-header (values h nil nil)))))
  ;; 2) ourNext key  -> signals a DH ratchet step
  (when (or (null (dr-their-next-pub s))
            (string= event-pubkey (dr-their-next-pub s)))
    (let ((h (with-ck (c (dr-our-next-priv s) event-pubkey) (try-dec-header enc-header c))))
      (when h (return-from decrypt-header (values h t nil)))))
  ;; 3) skipped header keys
  (let ((entry (gethash event-pubkey (dr-skipped s))))
    (when entry
      (dolist (k (car entry))
        (let ((h (try-dec-header enc-header k)))
          (when h (return-from decrypt-header (values h nil t)))))))
  (error "double-ratchet: failed to decrypt header"))

;;; --------------------------- public send / receive ------------------------

(defun dr-send-event (s text &key (kind *chat-kind*) (sender-pubkey nil) (tags nil))
  "Encrypt TEXT as an inner rumor and return a signed outer kind-1060 event
   hash-table (publish it). SENDER-PUBKEY sets the inner rumor's pubkey (our
   identity); defaults to all-zero dummy like the reference."
  (unless (dr-can-send-p s)
    (error "double-ratchet: cannot send yet (we're the responder; await first message)"))
  (let* ((now (unix-now))
         (rumor-pub (or sender-pubkey "0000000000000000000000000000000000000000000000000000000000000000"))
         (tagvec (coerce (mapcar (lambda (tg) (coerce tg 'vector)) (or tags '())) 'vector))
         (rumor (ht "pubkey" rumor-pub "created_at" now "kind" kind
                    "tags" tagvec "content" text))
         (rid (event-id-hex rumor-pub now kind tagvec text)))
    (setf (gethash "id" rumor) rid)
    (multiple-value-bind (header ciphertext) (ratchet-encrypt s (jstr rumor))
      (let ((enc-header (with-ck (dh (dr-our-current-priv s) (dr-their-next-pub s))
                          (nip44:nip44-encrypt-ck (jstr header) dh))))
        (sign-event (dr-our-current-priv s) (dr-our-current-pub s) now *message-kind*
                    (vector (vector "header" enc-header)) ciphertext)))))

(defun dr-receive-event (s event)
  "EVENT is the outer kind-1060 hash-table. Returns the decrypted inner rumor
   hashtable, or NIL if it couldn't be processed (state left unchanged on error)."
  (let* ((pubkey (gethash "pubkey" event))
         (content (gethash "content" event))
         (tags (gethash "tags" event))
         (enc-header (and (vectorp tags) (plusp (length tags))
                          (let ((t0 (aref tags 0)))
                            (and (vectorp t0) (>= (length t0) 2) (aref t0 1))))))
    (unless enc-header (return-from dr-receive-event nil))
    (let ((snapshot (copy-state s)) (restored nil))
      (unwind-protect
           (handler-case
               (multiple-value-bind (header should-ratchet is-skipped)
                   (decrypt-header s pubkey enc-header)
                 (when (and (not is-skipped)
                            (not (equal (dr-their-next-pub s) (jget header "nextPublicKey"))))
                   (setf (dr-their-current-pub s) (dr-their-next-pub s)
                         (dr-their-next-pub s) (jget header "nextPublicKey")))
                 (cond
                   ((not is-skipped)
                    (when should-ratchet
                      (skip-message-keys s (jget header "previousChainLength") pubkey)
                      (ratchet-step s)))
                   (t
                    (let ((entry (gethash pubkey (dr-skipped s))))
                      (unless (and entry (gethash (jget header "number") (cdr entry)))
                        (return-from dr-receive-event nil)))))
                 (json:parse (ratchet-decrypt s header content pubkey)))
             (error ()
               (restore-state s snapshot)
               (setf restored t)
               nil))
        (unless restored (dr-free snapshot))))))

;;; ----------------------------- state snapshot -----------------------------

(defun copy-state (s)
  "A deep copy of S: every key is a fresh owned fixed buffer (free with DR-FREE)."
  (let ((sk (make-hash-table :test 'equal)))
    (maphash (lambda (k v)
               (let ((mk (make-hash-table :test 'eql)))
                 (maphash (lambda (n m) (setf (gethash n mk) (%own-copy m))) (cdr v))
                 (setf (gethash k sk) (cons (mapcar #'%own-copy (car v)) mk))))
             (dr-skipped s))
    (make-dr-session
     :root-key (%own-copy (dr-root-key s)) :their-current-pub (dr-their-current-pub s)
     :their-next-pub (dr-their-next-pub s)
     :our-current-priv (%own-copy (dr-our-current-priv s)) :our-current-pub (dr-our-current-pub s)
     :our-next-priv (%own-copy (dr-our-next-priv s)) :our-next-pub (dr-our-next-pub s)
     :recv-chain (%own-copy (dr-recv-chain s)) :send-chain (%own-copy (dr-send-chain s))
     :send-n (dr-send-n s) :recv-n (dr-recv-n s) :prev-send-n (dr-prev-send-n s)
     :skipped sk)))

(defun restore-state (s snap)
  "Make S the state SNAP holds: S's own keys are wiped and released, SNAP's are
adopted (SNAP must not be used or freed afterwards)."
  (dr-free s)
  (setf (dr-root-key s) (dr-root-key snap)
        (dr-their-current-pub s) (dr-their-current-pub snap)
        (dr-their-next-pub s) (dr-their-next-pub snap)
        (dr-our-current-priv s) (dr-our-current-priv snap)
        (dr-our-current-pub s) (dr-our-current-pub snap)
        (dr-our-next-priv s) (dr-our-next-priv snap)
        (dr-our-next-pub s) (dr-our-next-pub snap)
        (dr-recv-chain s) (dr-recv-chain snap)
        (dr-send-chain s) (dr-send-chain snap)
        (dr-send-n s) (dr-send-n snap)
        (dr-recv-n s) (dr-recv-n snap)
        (dr-prev-send-n s) (dr-prev-send-n snap)
        (dr-skipped s) (dr-skipped snap)))

;;; --------------------------- state persistence ----------------------------
;;; Our own JSON form (we are the only reader).  DR-STATE->JSON is an explicit EXPORT
;;; of every secret the session holds, as hex, for persistence; JSON->DR-STATE brings
;;; them back into fixed memory.

(defun b->h (b) (and b (bytes->hex b)))

(defun dr-state->json (s)
  (let ((sk (make-hash-table :test 'equal)))
    (maphash (lambda (sender v)
               (let ((mks (make-hash-table :test 'equal)))
                 (maphash (lambda (n m) (setf (gethash (princ-to-string n) mks) (b->h m))) (cdr v))
                 (setf (gethash sender sk)
                       (ht "headerKeys" (coerce (mapcar #'b->h (car v)) 'vector)
                           "messageKeys" mks))))
             (dr-skipped s))
    (jstr (ht "rootKey" (b->h (dr-root-key s))
              "theirCurrentPub" (dr-their-current-pub s)
              "theirNextPub" (dr-their-next-pub s)
              "ourCurrentPriv" (b->h (dr-our-current-priv s))
              "ourCurrentPub" (dr-our-current-pub s)
              "ourNextPriv" (b->h (dr-our-next-priv s))
              "ourNextPub" (dr-our-next-pub s)
              "recvChain" (b->h (dr-recv-chain s))
              "sendChain" (b->h (dr-send-chain s))
              "sendN" (dr-send-n s) "recvN" (dr-recv-n s) "prevSendN" (dr-prev-send-n s)
              "skipped" sk))))

(defun json->dr-state (json)
  (let* ((p (json:parse json))
         (sk (make-hash-table :test 'equal))
         (skp (gethash "skipped" p)))
    (when (hash-table-p skp)
      (maphash (lambda (sender v)
                 (let ((mks (make-hash-table :test 'eql))
                       (mksrc (gethash "messageKeys" v)))
                   (when (hash-table-p mksrc)
                     (maphash (lambda (n h) (setf (gethash (parse-integer n) mks) (%own-from-hex h))) mksrc))
                   (setf (gethash sender sk)
                         (cons (map 'list #'%own-from-hex (gethash "headerKeys" v)) mks))))
               skp))
    (make-dr-session
     :root-key (%own-from-hex (gethash "rootKey" p))
     :their-current-pub (gethash "theirCurrentPub" p)
     :their-next-pub (gethash "theirNextPub" p)
     :our-current-priv (%own-from-hex (gethash "ourCurrentPriv" p))
     :our-current-pub (gethash "ourCurrentPub" p)
     :our-next-priv (%own-from-hex (gethash "ourNextPriv" p))
     :our-next-pub (gethash "ourNextPub" p)
     :recv-chain (%own-from-hex (gethash "recvChain" p))
     :send-chain (%own-from-hex (gethash "sendChain" p))
     :send-n (gethash "sendN" p) :recv-n (gethash "recvN" p)
     :prev-send-n (gethash "prevSendN" p)
     :skipped sk)))

;;; ------------------------------ NIP-118 invites ---------------------------

(defun make-public-invite (identity-priv identity-pub-hex)
  "Build a public double-ratchet invite (kind 30078) signed by our identity
(IDENTITY-PRIV a keypair or fixed secret).  Returns (values event-hashtable eph-priv
eph-pub-hex shared-secret-hex); EPH-PRIV is an owned fixed key (DR-FREE-KEY it when
the invite is retired)."
  (let* ((eph-priv (gen-priv))
         (eph-pub (priv->pub-hex eph-priv))
         (ss-hex (bytes->hex (u:random-bytes 32)))
         (now (unix-now))
         (tags (vector (vector "ephemeralKey" eph-pub)
                       (vector "sharedSecret" ss-hex)
                       (vector "d" "double-ratchet/invites/public")
                       (vector "l" "double-ratchet/invites"))))
    (values (sign-event identity-priv identity-pub-hex now *invite-kind* tags "")
            eph-priv eph-pub ss-hex)))

(defun decrypt-invite-response (envelope-content envelope-sender-pub
                                eph-priv identity-priv shared-secret-bytes)
  "Invite-response (kind 1059) -> (values invitee-identity invitee-session-pub owner-pub)."
  (let* ((decrypted (with-ck (c eph-priv envelope-sender-pub)
                      (nip44:nip44-decrypt-ck envelope-content c)))
         (inner (json:parse decrypted))
         (invitee-identity (gethash "pubkey" inner))
         (dh-encrypted (nip44:nip44-decrypt-ck (gethash "content" inner) shared-secret-bytes))
         (payload-str (with-ck (c identity-priv invitee-identity)
                        (nip44:nip44-decrypt-ck dh-encrypted c)))
         (payload (handler-case (json:parse payload-str) (error () nil))))
    (if (hash-table-p payload)
        (values invitee-identity (gethash "sessionKey" payload) (gethash "ownerPublicKey" payload))
        (values invitee-identity payload-str nil))))

(defun session-from-invite-response (invitee-session-pub eph-priv shared-secret-bytes)
  "Create our (responder) session after decrypting an invite response.  EPH-PRIV and
SHARED-SECRET-BYTES are copied into the session."
  (dr-init invitee-session-pub eph-priv nil shared-secret-bytes))

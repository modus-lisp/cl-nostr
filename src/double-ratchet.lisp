;;;; src/double-ratchet.lisp — the Nostr Double Ratchet ("Secure DMs").
;;;;
;;;; Native Lisp port of the Nostr "Double Ratchet with header encryption"
;;;; (Signal-style), the scheme behind yakihonne's "Secure DMs" and the NIP-118
;;;; invite handshake.  Wire-compatible with the reference implementation
;;;; `nostr-double-ratchet` (mmalmi / iris).
;;;;
;;;; Ported from battle.crypto.double-ratchet — "validated cross-implementation
;;;; against the reference acting as the peer" — with the crypto backend rewired
;;;; onto cl-nostr's stack: SECP256K1-FAST for ECDH/Schnorr and cl-nostr.nip44
;;;; for the v2 payloads.  Nothing else in the ratchet logic changes.
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
(defun hex->bytes (h) (ic:hex-string-to-byte-array h))
(defun bytes->hex (b) (string-downcase (ic:byte-array-to-hex-string b)))
(defun utf8 (s) (sb-ext:string-to-octets s :external-format :utf-8))

(defun gen-priv ()
  "Random secp256k1 secret key as an integer."
  (secp:bytes-to-int (u:random-bytes 32)))

(defun priv->pub-hex (priv-int)
  "x-only schnorr public key, lowercase hex (nostr getPublicKey)."
  (bytes->hex (schnorr:pubkey-xonly priv-int)))

(defun ck (priv-int pub-hex)
  "NIP-44 conversation key between our PRIV-INT and their PUB-HEX (x-only)."
  (nip44:conversation-key priv-int (hex->bytes pub-hex)))

(defun hmac-sha256 (key msg)
  (let ((h (ic:make-hmac key :sha256))) (ic:update-hmac h msg) (ic:hmac-digest h)))

(defparameter +chain-step+
  (make-array 1 :element-type '(unsigned-byte 8) :initial-element 1)
  "The single-byte [1] info used to ratchet a symmetric chain key forward.")

(defun kdf (in1 in2 n)
  "HKDF-SHA256 as the reference uses it: prk = HMAC(key=in2, msg=in1),
   out_i = HMAC(prk, [i,1]) for i=1..N. Returns a list of N 32-byte arrays."
  (let ((prk (hmac-sha256 in2 in1)))
    (loop for i from 1 to n
          collect (hmac-sha256 prk (make-array 2 :element-type '(unsigned-byte 8)
                                                  :initial-contents (list i 1))))))

;;; ------------------------------ JSON helpers ------------------------------

(defun jstr (obj) (with-output-to-string (s) (jzon:stringify obj :stream s)))

(defun ht (&rest kvs)
  (let ((h (make-hash-table :test 'equal)))
    (loop for (k v) on kvs by #'cddr do (setf (gethash k h) v))
    h))

(defun jget (parsed key) (and (hash-table-p parsed) (gethash key parsed)))

;;; --------------------------- event id + signing ---------------------------

(defun event-id-hex (pub created kind tags content)
  (let ((ser (jstr (vector 0 pub created kind tags content))))
    (bytes->hex (ic:digest-sequence :sha256 (utf8 ser)))))

(defun sign-event (priv-int pub-hex created kind tags content)
  "Build a signed Nostr event hash-table (NIP-01)."
  (let* ((id (event-id-hex pub-hex created kind tags content))
         (sig (bytes->hex (schnorr:schnorr-sign priv-int (hex->bytes id)))))
    (ht "id" id "pubkey" pub-hex "created_at" created "kind" kind
        "tags" tags "content" content "sig" sig)))

(defun unix-now () (- (get-universal-time) (encode-universal-time 0 0 0 1 1 1970 0)))

;;; ------------------------------ session state ------------------------------

(defstruct (dr-session (:conc-name dr-))
  root-key                ; (unsigned-byte 8) vector
  their-current-pub       ; hex | nil
  their-next-pub          ; hex
  our-current-priv our-current-pub  ; int|nil / hex|nil
  our-next-priv our-next-pub        ; int / hex
  recv-chain send-chain   ; bytes | nil
  (send-n 0) (recv-n 0) (prev-send-n 0)
  skipped)                ; equal hashtable: sender-hex -> (cons header-keys-list msgkeys-ht)

(defun dr-can-send-p (s)
  (and (dr-their-next-pub s) (dr-our-current-priv s) t))

(defun dr-init (their-eph-pub our-eph-priv-int is-initiator shared-secret-bytes)
  "Initialise a session. IS-INITIATOR = the one who sends first (invitee/
   accept side). The responder (our bot) starts with no sending chain and
   must receive a message before it can reply."
  (if is-initiator
      (let* ((our-next-priv (gen-priv))
             (parts (kdf shared-secret-bytes (ck our-next-priv their-eph-pub) 2)))
        (make-dr-session
         :root-key (first parts)
         :their-next-pub their-eph-pub
         :our-current-priv our-eph-priv-int :our-current-pub (priv->pub-hex our-eph-priv-int)
         :our-next-priv our-next-priv :our-next-pub (priv->pub-hex our-next-priv)
         :send-chain (second parts)
         :skipped (make-hash-table :test 'equal)))
      (make-dr-session
       :root-key shared-secret-bytes
       :their-next-pub their-eph-pub
       :our-current-priv nil :our-current-pub nil
       :our-next-priv our-eph-priv-int :our-next-pub (priv->pub-hex our-eph-priv-int)
       :send-chain nil
       :skipped (make-hash-table :test 'equal))))

;;; ------------------------------- ratchet ----------------------------------

(defun ratchet-encrypt (s plaintext)
  "Returns (values header-hashtable ciphertext-string)."
  (destructuring-bind (new-sck mk) (kdf (dr-send-chain s) +chain-step+ 2)
    (setf (dr-send-chain s) new-sck)
    (let ((header (ht "number" (dr-send-n s)
                      "nextPublicKey" (dr-our-next-pub s)
                      "previousChainLength" (dr-prev-send-n s))))
      (incf (dr-send-n s))
      (values header (nip44:nip44-encrypt-ck plaintext mk)))))

(defun ratchet-decrypt (s header ciphertext sender)
  (let ((skipped-pt (try-skipped-message-keys s header ciphertext sender)))
    (if skipped-pt
        skipped-pt
        (progn
          (skip-message-keys s (jget header "number") sender)
          (destructuring-bind (new-rck mk) (kdf (dr-recv-chain s) +chain-step+ 2)
            (setf (dr-recv-chain s) new-rck)
            (incf (dr-recv-n s))
            (nip44:nip44-decrypt-ck ciphertext mk))))))

(defun ratchet-step (s)
  (setf (dr-prev-send-n s) (dr-send-n s)
        (dr-send-n s) 0
        (dr-recv-n s) 0)
  (let ((parts1 (kdf (dr-root-key s) (ck (dr-our-next-priv s) (dr-their-next-pub s)) 2)))
    (setf (dr-recv-chain s) (second parts1))
    (setf (dr-our-current-priv s) (dr-our-next-priv s)
          (dr-our-current-pub s)  (dr-our-next-pub s))
    (let ((next (gen-priv)))
      (setf (dr-our-next-priv s) next
            (dr-our-next-pub s)  (priv->pub-hex next)))
    (let ((parts2 (kdf (first parts1) (ck (dr-our-next-priv s) (dr-their-next-pub s)) 2)))
      (setf (dr-root-key s)  (first parts2)
            (dr-send-chain s) (second parts2)))))

;;; --------------------------- skipped message keys --------------------------

(defun ensure-skip-entry (s sender)
  (or (gethash sender (dr-skipped s))
      (setf (gethash sender (dr-skipped s))
            (cons '() (make-hash-table :test 'eql)))))   ; (header-keys . msgkeys-ht)

(defun skip-message-keys (s until sender)
  (when (<= until (dr-recv-n s)) (return-from skip-message-keys))
  (when (> until (+ (dr-recv-n s) *max-skip*))
    (error "double-ratchet: too many skipped messages"))
  (let ((fresh (not (gethash sender (dr-skipped s)))))
    (let ((entry (ensure-skip-entry s sender)))
      (when fresh
        ;; cache the header keys for this sender (current + next)
        (when (dr-our-current-priv s)
          (let ((cur (ck (dr-our-current-priv s) sender)))
            (unless (member cur (car entry) :test #'equalp) (push cur (car entry)))))
        (let ((nxt (ck (dr-our-next-priv s) sender)))
          (unless (member nxt (car entry) :test #'equalp) (push nxt (car entry)))))
      (loop while (< (dr-recv-n s) until) do
        (destructuring-bind (new-rck mk) (kdf (dr-recv-chain s) +chain-step+ 2)
          (setf (dr-recv-chain s) new-rck)
          (setf (gethash (dr-recv-n s) (cdr entry)) mk)
          (incf (dr-recv-n s)))))))

(defun try-skipped-message-keys (s header ciphertext sender)
  (let ((entry (gethash sender (dr-skipped s))))
    (when entry
      (let ((mk (gethash (jget header "number") (cdr entry))))
        (when mk
          (remhash (jget header "number") (cdr entry))
          (when (zerop (hash-table-count (cdr entry)))
            (remhash sender (dr-skipped s)))
          (nip44:nip44-decrypt-ck ciphertext mk))))))

;;; ------------------------------ header decrypt ----------------------------

(defun try-dec-header (enc-header conv-key)
  "Returns the parsed header hashtable or NIL on failure."
  (handler-case (jzon:parse (nip44:nip44-decrypt-ck enc-header conv-key))
    (error () nil)))

(defun decrypt-header (s event-pubkey enc-header)
  "Returns (values header should-ratchet is-skipped). Signals on total failure."
  ;; 1) ourCurrent key
  (when (and (dr-our-current-priv s)
             (or (null (dr-their-current-pub s))
                 (string= event-pubkey (dr-their-current-pub s))
                 (string= event-pubkey (dr-their-next-pub s))))
    (let ((h (try-dec-header enc-header (ck (dr-our-current-priv s) event-pubkey))))
      (when h (return-from decrypt-header (values h nil nil)))))
  ;; 2) ourNext key  -> signals a DH ratchet step
  (when (or (null (dr-their-next-pub s))
            (string= event-pubkey (dr-their-next-pub s)))
    (let ((h (try-dec-header enc-header (ck (dr-our-next-priv s) event-pubkey))))
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
      (let* ((dh (ck (dr-our-current-priv s) (dr-their-next-pub s)))
             (enc-header (nip44:nip44-encrypt-ck (jstr header) dh)))
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
                            (and (vectorp t0) (>= (length t0) 2) (aref t0 1)))))
         (snapshot (copy-state s)))
    (unless enc-header (return-from dr-receive-event nil))
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
          (let ((text (ratchet-decrypt s header content pubkey)))
            (jzon:parse text)))
      (error ()
        (restore-state s snapshot)
        nil))))

;;; ----------------------------- state snapshot -----------------------------

(defun copy-state (s)
  (let ((sk (make-hash-table :test 'equal)))
    (maphash (lambda (k v)
               (let ((mk (make-hash-table :test 'eql)))
                 (maphash (lambda (n m) (setf (gethash n mk) m)) (cdr v))
                 (setf (gethash k sk) (cons (copy-list (car v)) mk))))
             (dr-skipped s))
    (make-dr-session
     :root-key (dr-root-key s) :their-current-pub (dr-their-current-pub s)
     :their-next-pub (dr-their-next-pub s)
     :our-current-priv (dr-our-current-priv s) :our-current-pub (dr-our-current-pub s)
     :our-next-priv (dr-our-next-priv s) :our-next-pub (dr-our-next-pub s)
     :recv-chain (dr-recv-chain s) :send-chain (dr-send-chain s)
     :send-n (dr-send-n s) :recv-n (dr-recv-n s) :prev-send-n (dr-prev-send-n s)
     :skipped sk)))

(defun restore-state (s snap)
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
;;; Our own JSON form (we are the only reader). Bytes -> hex, ints -> hex.

(defun b->h (b) (and b (bytes->hex b)))
(defun h->b (h) (and h (hex->bytes h)))
(defun i->h (i) (and i (format nil "~64,'0x" i)))
(defun h->i (h) (and h (parse-integer h :radix 16)))

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
              "ourCurrentPriv" (i->h (dr-our-current-priv s))
              "ourCurrentPub" (dr-our-current-pub s)
              "ourNextPriv" (i->h (dr-our-next-priv s))
              "ourNextPub" (dr-our-next-pub s)
              "recvChain" (b->h (dr-recv-chain s))
              "sendChain" (b->h (dr-send-chain s))
              "sendN" (dr-send-n s) "recvN" (dr-recv-n s) "prevSendN" (dr-prev-send-n s)
              "skipped" sk))))

(defun json->dr-state (json)
  (let* ((p (jzon:parse json))
         (sk (make-hash-table :test 'equal))
         (skp (gethash "skipped" p)))
    (when (hash-table-p skp)
      (maphash (lambda (sender v)
                 (let ((mks (make-hash-table :test 'eql))
                       (mksrc (gethash "messageKeys" v)))
                   (when (hash-table-p mksrc)
                     (maphash (lambda (n h) (setf (gethash (parse-integer n) mks) (h->b h))) mksrc))
                   (setf (gethash sender sk)
                         (cons (map 'list #'h->b (gethash "headerKeys" v)) mks))))
               skp))
    (make-dr-session
     :root-key (h->b (gethash "rootKey" p))
     :their-current-pub (gethash "theirCurrentPub" p)
     :their-next-pub (gethash "theirNextPub" p)
     :our-current-priv (h->i (gethash "ourCurrentPriv" p))
     :our-current-pub (gethash "ourCurrentPub" p)
     :our-next-priv (h->i (gethash "ourNextPriv" p))
     :our-next-pub (gethash "ourNextPub" p)
     :recv-chain (h->b (gethash "recvChain" p))
     :send-chain (h->b (gethash "sendChain" p))
     :send-n (gethash "sendN" p) :recv-n (gethash "recvN" p)
     :prev-send-n (gethash "prevSendN" p)
     :skipped sk)))

;;; ------------------------------ NIP-118 invites ---------------------------

(defun make-public-invite (identity-priv-int identity-pub-hex)
  "Build a public double-ratchet invite (kind 30078) signed by our identity.
   Returns (values event-hashtable eph-priv-int eph-pub-hex shared-secret-hex)."
  (let* ((eph-priv (gen-priv))
         (eph-pub (priv->pub-hex eph-priv))
         (ss-hex (bytes->hex (u:random-bytes 32)))
         (now (unix-now))
         (tags (vector (vector "ephemeralKey" eph-pub)
                       (vector "sharedSecret" ss-hex)
                       (vector "d" "double-ratchet/invites/public")
                       (vector "l" "double-ratchet/invites"))))
    (values (sign-event identity-priv-int identity-pub-hex now *invite-kind* tags "")
            eph-priv eph-pub ss-hex)))

(defun decrypt-invite-response (envelope-content envelope-sender-pub
                                eph-priv-int identity-priv-int shared-secret-bytes)
  "Invite-response (kind 1059) -> (values invitee-identity invitee-session-pub owner-pub)."
  (let* ((decrypted (nip44:nip44-decrypt-ck envelope-content
                                            (ck eph-priv-int envelope-sender-pub)))
         (inner (jzon:parse decrypted))
         (invitee-identity (gethash "pubkey" inner))
         (dh-encrypted (nip44:nip44-decrypt-ck (gethash "content" inner) shared-secret-bytes))
         (payload-str (nip44:nip44-decrypt-ck dh-encrypted
                                              (ck identity-priv-int invitee-identity)))
         (payload (handler-case (jzon:parse payload-str) (error () nil))))
    (if (hash-table-p payload)
        (values invitee-identity (gethash "sessionKey" payload) (gethash "ownerPublicKey" payload))
        (values invitee-identity payload-str nil))))

(defun session-from-invite-response (invitee-session-pub eph-priv-int shared-secret-bytes)
  "Create our (responder) session after decrypting an invite response."
  (dr-init invitee-session-pub eph-priv-int nil shared-secret-bytes))

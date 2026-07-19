;;;; src/nip44.lisp — NIP-44 v2 encrypted payloads.
;;;;
;;;; secp256k1 ECDH -> HKDF-SHA256 -> ChaCha20 + HMAC-SHA256, base64.  This is
;;;; the encryption layer NIP-17 private DMs (and the Double Ratchet) are built
;;;; on.  Ported byte-for-byte from battle.crypto.nip44 — which was validated
;;;; against the canonical nostr-protocol/nips nip44.vectors.json — with the
;;;; ONLY change being the ECDH backend: battle's own secp256k1 is replaced by
;;;; SECP256K1-FAST (secp-mul-point / lift-x).  The HMAC / ChaCha20 / HKDF /
;;;; base64 primitives (ironclad + cl-base64) are unchanged, so ciphertext is
;;;; bit-identical to the validated source.
;;;;
;;;; ECDH mapping (the crux of the port):
;;;;   shared secret = x-coordinate of  privkey * lift_x(peer-x-only-pubkey)
;;;;   battle:  (car (secp:secp-mul-point priv (battle-lift-x x)))
;;;;   here:    (secp:secp-x (secp:secp-mul-point priv (sch:lift-x x)))
;;;; Both lift the x-only pubkey to its even-Y point and take the product's x.

(in-package #:cl-nostr.nip44)

(defun cat (&rest vs) (apply #'concatenate '(vector (unsigned-byte 8)) vs))
(defun u8 (n) (make-array n :element-type '(unsigned-byte 8)))

(defun hmac-sha256 (key msg)
  (let ((h (ic:make-hmac key :sha256))) (ic:update-hmac h msg) (ic:hmac-digest h)))

(defun hkdf-extract (salt ikm) (hmac-sha256 salt ikm))

(defun hkdf-expand (prk info len)
  (let ((blocks '()) (prev (u8 0)))
    (dotimes (i (ceiling len 32))
      (let ((cur (hmac-sha256 prk (cat prev info (vector (1+ i))))))
        (push cur blocks) (setf prev cur)))
    (subseq (apply #'cat (nreverse blocks)) 0 len)))

(defun chacha20 (key nonce12 data)
  "Raw ChaCha20 (IETF 12-byte nonce, block counter 0)."
  (let ((cipher (ic:make-cipher :chacha :key key :mode :stream :initialization-vector nonce12))
        (out (u8 (length data))))
    (ic:encrypt cipher data out)
    out))

(defun conversation-key (privkey-int pubkey-x-bytes)
  "HKDF-extract(salt='nip44-v2', IKM = ECDH shared x).  32 bytes.
PRIVKEY-INT is our secret scalar (integer); PUBKEY-X-BYTES is the peer's
32-byte x-only public key."
  (secp:secp-init)
  (let* ((pt (or (sch:lift-x (secp:bytes-to-int pubkey-x-bytes))
                 (error "nip44: peer pubkey is not a valid curve point")))
         (shared-x (secp:int-to-bytes32 (secp:secp-x (secp:secp-mul-point privkey-int pt)))))
    (hkdf-extract (ic:ascii-string-to-byte-array "nip44-v2") shared-x)))

(defun message-keys (ck nonce32)
  (let ((k (hkdf-expand ck nonce32 76)))
    (values (subseq k 0 32) (subseq k 32 44) (subseq k 44 76))))

(defun calc-padded-len (len)
  "NIP-44: next_power = 1 << (floor(log2(len-1))+1) = ash 1 (integer-length (1- len))."
  (if (<= len 32) 32
      (let* ((next-power (ash 1 (integer-length (1- len))))
             (chunk (if (<= next-power 256) 32 (floor next-power 8))))
        (* chunk (1+ (floor (1- len) chunk))))))

(defun pad (plaintext-bytes)
  (let* ((len (length plaintext-bytes)))
    (when (or (< len 1) (> len 65535)) (error "nip44: bad plaintext length ~d" len))
    (let ((out (u8 (+ 2 (calc-padded-len len)))))
      (setf (aref out 0) (ldb (byte 8 8) len) (aref out 1) (ldb (byte 8 0) len))
      (replace out plaintext-bytes :start1 2)
      out)))

(defun unpad (padded)
  (let* ((len (logior (ash (aref padded 0) 8) (aref padded 1))))
    (when (or (zerop len) (/= (length padded) (+ 2 (calc-padded-len len))))
      (error "nip44: invalid padding"))
    (subseq padded 2 (+ 2 len))))

(defun nip44-encrypt-with-nonce (plaintext-bytes ck nonce32)
  "The deterministic core: encrypt PLAINTEXT-BYTES under conversation key CK with
an explicit 32-byte NONCE32.  Returns the base64 NIP-44 payload."
  (multiple-value-bind (ck-key ck-nonce hmac-key) (message-keys ck nonce32)
    (let* ((ciphertext (chacha20 ck-key ck-nonce (pad plaintext-bytes)))
           (mac (hmac-sha256 hmac-key (cat nonce32 ciphertext))))
      (b64:usb8-array-to-base64-string (cat (vector 2) nonce32 ciphertext mac)))))

(defun nip44-encrypt (privkey-int pubkey-hex plaintext)
  "Encrypt a UTF-8 string to PUBKEY-HEX (x-only).  Returns base64 payload."
  (nip44-encrypt-with-nonce (u:string->utf8 plaintext)
                            (conversation-key privkey-int (u:hex->bytes pubkey-hex))
                            (u:random-bytes 32)))

(defun nip44-encrypt-ck (plaintext ck)
  "Encrypt a UTF-8 string with a raw 32-byte conversation key CK (the form
nostr-tools' nip44.encrypt(plaintext, key) takes — used by the double ratchet,
where keys are derived directly, not from priv/pub).  Random nonce."
  (nip44-encrypt-with-nonce (u:string->utf8 plaintext) ck (u:random-bytes 32)))

(defun nip44-decrypt-ck (payload ck)
  "Decrypt a base64 NIP-44 payload with a raw 32-byte conversation key CK."
  (when (or (zerop (length payload)) (char= (char payload 0) #\#))
    (error "nip44: unknown version"))
  (let* ((data (b64:base64-string-to-usb8-array payload))
         (nonce (subseq data 1 33))
         (ct (subseq data 33 (- (length data) 32)))
         (mac (subseq data (- (length data) 32))))
    (unless (= (aref data 0) 2) (error "nip44: unsupported version ~d" (aref data 0)))
    (multiple-value-bind (ck-key ck-nonce hmac-key) (message-keys ck nonce)
      (unless (equalp mac (hmac-sha256 hmac-key (cat nonce ct))) (error "nip44: bad MAC"))
      (u:utf8->string (unpad (chacha20 ck-key ck-nonce ct))))))

(defun nip44-decrypt (privkey-int pubkey-hex payload)
  "Decrypt a base64 NIP-44 payload from PUBKEY-HEX.  Returns the UTF-8 string."
  (nip44-decrypt-ck payload (conversation-key privkey-int (u:hex->bytes pubkey-hex))))

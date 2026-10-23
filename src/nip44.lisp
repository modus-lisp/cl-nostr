;;;; src/nip44.lisp — NIP-44 v2 encrypted payloads.
;;;;
;;;; secp256k1 ECDH -> HKDF-SHA256 -> ChaCha20 + HMAC-SHA256, base64.  This is
;;;; the encryption layer NIP-17 private DMs (and the Double Ratchet) are built
;;;; on, and the one the UDP datagrams carry in raw form.  Validated against the canonical nostr-protocol/nips
;;;; nip44.vectors.json.  ECDH is SECP256K1-FAST's constant-time ECDH-X over
;;;; lift_x(peer); the HMAC / HKDF / ChaCha20 primitives are natrium's, base64 is
;;;; cl-base64.
;;;;
;;;; ECDH shape:
;;;;   shared secret = x-coordinate of  privkey * lift_x(peer-x-only-pubkey)
;;;; lift-x lifts the x-only pubkey to its even-Y point; we take the product's x.
;;;;
;;;; SECRETS: the private key is a KEYPAIR or fixed buffer (see keys.lisp); the shared
;;;; x, the conversation key and the per-message ChaCha / HMAC keys are all fixed
;;;; scratch, wiped on exit.  The private key never becomes an integer.

(in-package #:cl-nostr.nip44)

(defun cat (&rest vs) (coerce (apply #'concatenate '(vector (unsigned-byte 8)) vs)
                              '(simple-array (unsigned-byte 8) (*))))
(defun %u8v (v) (coerce v '(simple-array (unsigned-byte 8) (*))))
(defun u8 (n) (make-array n :element-type '(unsigned-byte 8)))

(defun hmac-sha256 (key msg) (na:hmac-sha256 (%u8v key) (%u8v msg)))

(defun chacha20 (key nonce12 data)
  "Raw ChaCha20 (IETF 12-byte nonce, block counter 0)."
  (na:chacha20 key nonce12 (%u8v data) :counter 0))

(defparameter +salt+ (u:string->utf8 "nip44-v2"))

(defun %conversation-key-into (sec pubkey-x-bytes out)
  "HKDF-extract(salt='nip44-v2', IKM = ECDH shared x) into OUT (fixed)."
  (secp:secp-init)
  (let ((pt (or (sch:lift-x (secp:bytes-to-int pubkey-x-bytes))
                (error "nip44: peer pubkey is not a valid curve point"))))
    (gossamer:with-fixed-scratch ((shared :octets 32))
      (secp256k1-fast.ecdh:ecdh-x (cl-nostr.keys:secret-key-of sec) pt shared)
      (na:hmac-sha256-into +salt+ shared out))))

(defun conversation-key (sec pubkey-x-bytes)
  "The NIP-44 conversation key between SEC (a keypair or fixed secret) and the peer's
32-byte x-only PUBKEY-X-BYTES, as a POOLED fixed 32-byte buffer: FIXED:FREE it when
done (or use NIP44-ENCRYPT / NIP44-DECRYPT, which never let it out)."
  (let ((out (gossamer:acquire :octets 32)))
    (handler-case (%conversation-key-into sec pubkey-x-bytes out)
      (error (e) (gossamer:free out) (error e)))))

(defmacro with-message-keys ((ck-key ck-nonce hmac-key) ck nonce32 &body body)
  "Bind the three per-message keys (fixed scratch) expanded from CK and NONCE32."
  (let ((okm (gensym "OKM")))
    `(gossamer:with-fixed-scratch ((,okm :octets 76) (,ck-key :octets 32) (,ck-nonce :octets 12)
                                (,hmac-key :octets 32))
       (na:hkdf-expand-into :sha256 ,ck (%u8v ,nonce32) ,okm)
       (replace ,ck-key ,okm :end2 32)
       (replace ,ck-nonce ,okm :start2 32 :end2 44)
       (replace ,hmac-key ,okm :start2 44 :end2 76)
       ,@body)))

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
    (when (or (zerop len) (/= (length padded) (+ 2 (calc-padded-len len)))
              (notevery #'zerop (subseq padded (+ 2 len))))
      (error "nip44: invalid padding"))
    (subseq padded 2 (+ 2 len))))

(defun nip44-encrypt-octets-with-nonce (plaintext-bytes ck nonce32)
  "The deterministic core: encrypt PLAINTEXT-BYTES under conversation key CK with an
explicit 32-byte NONCE32.  Returns the raw NIP-44 v2 payload -- version byte, nonce,
ciphertext, MAC -- which is what a UDP datagram carries after the ephemeral key."
  (with-message-keys (ck-key ck-nonce hmac-key) ck nonce32
    (let* ((ciphertext (chacha20 ck-key ck-nonce (pad plaintext-bytes)))
           (mac (na:hmac-sha256-into hmac-key (list (%u8v nonce32) ciphertext) (u8 32))))
      (cat (vector 2) nonce32 ciphertext mac))))

(defun nip44-encrypt-with-nonce (plaintext-bytes ck nonce32)
  "The same payload as NIP44-ENCRYPT-OCTETS-WITH-NONCE, base64 encoded."
  (b64:usb8-array-to-base64-string (nip44-encrypt-octets-with-nonce plaintext-bytes ck nonce32)))

(defun nip44-encrypt (sec pubkey-hex plaintext)
  "Encrypt a UTF-8 string from SEC (keypair or fixed secret) to PUBKEY-HEX (x-only).
Returns the base64 payload."
  (gossamer:with-fixed-scratch ((ck :octets 32))
    (%conversation-key-into sec (u:hex->bytes pubkey-hex) ck)
    (nip44-encrypt-with-nonce (u:string->utf8 plaintext) ck (u:random-bytes 32))))

(defun nip44-encrypt-ck (plaintext ck)
  "Encrypt a UTF-8 string with a raw 32-byte conversation key CK (the form
nostr-tools' nip44.encrypt(plaintext, key) takes -- used by the double ratchet,
where keys are derived directly, not from priv/pub).  Random nonce."
  (nip44-encrypt-with-nonce (u:string->utf8 plaintext) ck (u:random-bytes 32)))

(defun nip44-decrypt-octets (ck data)
  "Decrypt a raw NIP-44 v2 payload DATA (version byte first) under conversation key CK.
Returns the plaintext octets.  Signals on any size, version, MAC or padding failure;
the MAC is checked before anything is decrypted."
  (let ((data (%u8v data)))
    (unless (<= 99 (length data) 65603) (error "nip44: invalid data size"))
    (unless (= (aref data 0) 2) (error "nip44: unsupported version ~d" (aref data 0)))
    (let ((nonce (subseq data 1 33))
          (ct (subseq data 33 (- (length data) 32)))
          (mac (subseq data (- (length data) 32))))
      (with-message-keys (ck-key ck-nonce hmac-key) ck nonce
        ;; constant-time comparison: the MAC is the authenticator
        (unless (na:bytes= mac (na:hmac-sha256-into hmac-key (list nonce ct) (u8 32))) (error "nip44: bad MAC"))
        (unpad (chacha20 ck-key ck-nonce ct))))))

(defun nip44-decrypt-ck (payload ck)
  "Decrypt a base64 NIP-44 payload with a raw 32-byte conversation key CK."
  (when (or (zerop (length payload)) (char= (char payload 0) #\#))
    (error "nip44: unknown version"))
  (unless (<= 132 (length payload) 87472) (error "nip44: invalid payload size"))
  (u:utf8->string (nip44-decrypt-octets ck (b64:base64-string-to-usb8-array payload))))

(defun nip44-decrypt (sec pubkey-hex payload)
  "Decrypt a base64 NIP-44 payload from PUBKEY-HEX to SEC (keypair or fixed secret)."
  (gossamer:with-fixed-scratch ((ck :octets 32))
    (%conversation-key-into sec (u:hex->bytes pubkey-hex) ck)
    (nip44-decrypt-ck payload ck)))

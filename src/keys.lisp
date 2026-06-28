;;;; src/keys.lisp — Nostr keys: a 32-byte secret scalar and an x-only public key.
;;;;
;;;; Nostr identity is a secp256k1 keypair; events are signed with BIP340 Schnorr
;;;; and the "pubkey" carried in an event is the 32-byte *x-only* public key.
;;;; The actual crypto is secp256k1-fast.schnorr (sch:); this file just frames it
;;;; in Nostr's terms (bytes/hex in, bytes/hex out).

(in-package #:cl-nostr.keys)

(defstruct (keypair (:constructor %make-keypair (secret-key public-key)))
  "A Nostr keypair.  SECRET-KEY is 32 bytes (the scalar); PUBLIC-KEY is the
32-byte x-only pubkey."
  (secret-key nil :type (simple-array (unsigned-byte 8) (32)) :read-only t)
  (public-key nil :type (simple-array (unsigned-byte 8) (32)) :read-only t))

;;; secp256k1-fast doesn't export a bytes->int, so derive it locally to avoid a
;;; dependency on internals: big-endian decode.
(defun %be->int (bytes)
  (let ((n 0)) (loop for b across bytes do (setf n (logior (ash n 8) b))) n))

(defun public-key-of-secret (secret)
  "The 32-byte x-only public key for a 32-byte (or hex) SECRET."
  (sch:pubkey-xonly (%be->int (u:->bytes32 secret))))

(defun keypair-from-secret (secret)
  "Build a keypair from a 32-byte (or 64-char hex) SECRET key."
  (let* ((sk (u:->bytes32 secret))
         (d (%be->int sk)))
    (when (or (zerop d) (>= d secp256k1-fast:*secp256k1-n*))
      (error "secret key out of range"))
    (%make-keypair sk (sch:pubkey-xonly d))))

(defun generate-keypair ()
  "Generate a fresh random keypair."
  (loop for sk = (u:random-bytes 32)
        for d = (%be->int sk)
        when (and (plusp d) (< d secp256k1-fast:*secp256k1-n*))
          do (return (%make-keypair sk (sch:pubkey-xonly d)))))

(defun make-keypair (&optional secret)
  "Generate a keypair, or rebuild one from SECRET (32 bytes / hex)."
  (if secret (keypair-from-secret secret) (generate-keypair)))

(defun secret-hex (keypair)
  "Lowercase hex of the secret key (handle with care)."
  (u:bytes->hex (keypair-secret-key keypair)))

(defun public-hex (keypair)
  "Lowercase hex of the x-only public key (this is the event \"pubkey\")."
  (u:bytes->hex (keypair-public-key keypair)))

(defun sign (keypair message32)
  "BIP340-sign a 32-byte MESSAGE (hex or bytes); returns 64 signature bytes."
  (sch:schnorr-sign (%be->int (keypair-secret-key keypair))
                    (u:->bytes32 message32)))

(defun verify (public-key message32 sig64)
  "T iff SIG64 is a valid signature of MESSAGE32 under x-only PUBLIC-KEY.
All args may be hex or bytes."
  (sch:schnorr-verify (u:->bytes32 public-key)
                      (u:->bytes32 message32)
                      (coerce (if (stringp sig64) (u:hex->bytes sig64) sig64)
                              '(vector (unsigned-byte 8)))))

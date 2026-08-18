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

;;; THE CURVE IS NOT THREAD-SAFE.  secp256k1-fast keeps mutable state across a
;;; scalar multiplication, so two threads signing at once do not merely contend —
;;; they corrupt each other.  Measured: of 80 concurrent signatures, 77 signalled
;;; and the 3 that returned were INVALID.  Silently invalid, which is the dangerous
;;; kind: the event looks complete, and the relay or Blossom server that rejects it
;;; says "signature invalid" about a key you know is good.
;;;
;;; Concurrency is normal in a Nostr client — a pool fans out, an uploader fans out
;;; — so the serialization belongs here, under everyone, rather than in a note asking
;;; every caller to remember.  A signature costs milliseconds; nothing here is a
;;; throughput bottleneck worth the risk of leaving it open.

(defvar *curve-lock* (bt:make-lock "secp256k1")
  "Serializes every call into secp256k1-fast; see the note above.")

;;; Deriving a pubkey is a scalar multiplication like signing is, so it takes it too.
(defun %pubkey-xonly (d)
  (bt:with-lock-held (*curve-lock*) (sch:pubkey-xonly d)))

(defun public-key-of-secret (secret)
  "The 32-byte x-only public key for a 32-byte (or hex) SECRET."
  (%pubkey-xonly (%be->int (u:->bytes32 secret))))

(defun keypair-from-secret (secret)
  "Build a keypair from a 32-byte (or 64-char hex) SECRET key."
  (let* ((sk (u:->bytes32 secret))
         (d (%be->int sk)))
    (when (or (zerop d) (>= d secp256k1-fast:*secp256k1-n*))
      (error "secret key out of range"))
    (%make-keypair sk (%pubkey-xonly d))))

(defun generate-keypair ()
  "Generate a fresh random keypair."
  (loop for sk = (u:random-bytes 32)
        for d = (%be->int sk)
        when (and (plusp d) (< d secp256k1-fast:*secp256k1-n*))
          do (return (%make-keypair sk (%pubkey-xonly d)))))

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
  "BIP340-sign a 32-byte MESSAGE (hex or bytes); returns 64 signature bytes.
Safe to call from several threads at once."
  (let ((d (%be->int (keypair-secret-key keypair)))
        (m (u:->bytes32 message32)))
    (bt:with-lock-held (*curve-lock*) (sch:schnorr-sign d m))))

(defun verify (public-key message32 sig64)
  "T iff SIG64 is a valid signature of MESSAGE32 under x-only PUBLIC-KEY.
All args may be hex or bytes.  Safe to call from several threads at once."
  (let ((pk (u:->bytes32 public-key))
        (m (u:->bytes32 message32))
        (sig (coerce (if (stringp sig64) (u:hex->bytes sig64) sig64)
                     '(vector (unsigned-byte 8)))))
    (bt:with-lock-held (*curve-lock*) (sch:schnorr-verify pk m sig))))

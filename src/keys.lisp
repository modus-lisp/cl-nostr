;;;; src/keys.lisp — Nostr keys: a 32-byte secret scalar and an x-only public key.
;;;;
;;;; Nostr identity is a secp256k1 keypair; events are signed with BIP340 Schnorr
;;;; and the "pubkey" carried in an event is the 32-byte *x-only* public key.
;;;; The actual crypto is secp256k1-fast.schnorr (sch:); this file just frames it
;;;; in Nostr's terms (bytes/hex in, bytes/hex out).

(in-package #:cl-nostr.keys)

(defstruct (keypair (:constructor %make-keypair (secret-key public-key)))
  "A Nostr keypair.  SECRET-KEY is the 32-byte scalar in a POOLED fixed buffer (never
moved by the collector; KEYPAIR-WIPE wipes it and returns it to the pool, after which
it is NIL); PUBLIC-KEY is the 32-byte x-only pubkey."
  (secret-key nil :type (or null (simple-array (unsigned-byte 8) (32))))
  (public-key nil :type (simple-array (unsigned-byte 8) (32)) :read-only t))

;;; THE CURVE WAS NOT THREAD-SAFE when this lock went in: secp256k1-fast kept mutable
;;; state across a scalar multiplication, and of 80 concurrent signatures 77
;;; signalled and the 3 that returned were INVALID.  secp256k1-fast now binds its own
;;; scratch per call, but the lock is cheap and stays: a signature costs milliseconds.
(defvar *curve-lock* (bt:make-lock "secp256k1")
  "Serializes every call into secp256k1-fast.")

(defun %import-secret (secret)
  "SECRET (32 bytes, or 64 hex chars) as a fresh fixed buffer.  The edge where a
secret from outside (a file, an nsec, a socket) enters fixed memory: the caller wipes
its own copy.  A heap byte vector we decoded from hex here is wiped before return."
  (etypecase secret
    (string (let ((b (u:hex->bytes secret)))
              (unless (= (length b) 32) (fill b 0) (error "expected 32 bytes, got ~d" (length b)))
              (prog1 (gossamer:pooled-copy b) (fill b 0))))
    (vector (unless (= (length secret) 32) (error "expected 32 bytes, got ~d" (length secret)))
            (gossamer:pooled-copy secret))))

(defun secret-key-of (sec)
  "The fixed 32-byte secret for SEC: a KEYPAIR or a fixed 32-byte buffer.  Anything
else -- an integer, a hex string, a heap byte vector -- is refused: import it once
with KEYPAIR-FROM-SECRET."
  (etypecase sec
    (keypair (or (keypair-secret-key sec) (error "this keypair has been wiped")))
    (vector (gossamer:check-fixed sec "Nostr secret key"))
    (t (error "a Nostr secret must be a KEYPAIR or a fixed 32-byte buffer, not ~a; import it with KEYPAIR-FROM-SECRET"
              (type-of sec)))))

(defun %pubkey-of-fixed (sk)
  (bt:with-lock-held (*curve-lock*) (sch:pubkey-xonly sk)))

(defun public-key-of-secret (secret)
  "The 32-byte x-only public key for SECRET (a keypair, fixed buffer, 32 bytes or hex)."
  (if (or (keypair-p secret) (and (vectorp secret) (not (stringp secret)) (gossamer:fixed-p secret)))
      (%pubkey-of-fixed (secret-key-of secret))
      (let ((sk (%import-secret secret)))
        (unwind-protect (%pubkey-of-fixed sk) (gossamer:free sk)))))

(defun keypair-from-secret (secret)
  "Build a keypair from a 32-byte (or 64-char hex) SECRET key, copied into fixed
memory.  The caller wipes its own copy of SECRET."
  (let ((sk (%import-secret secret)))
    (handler-case (gossamer:own (%make-keypair sk (%pubkey-of-fixed sk)) sk)
      (error (e) (gossamer:free sk) (error e)))))

(defun generate-keypair ()
  "Generate a fresh random keypair; the secret is generated straight into fixed memory."
  (let ((sk (gossamer:acquire :octets 32)))
    (loop
      (natrium:random-bytes-into sk)
      (handler-case (return (gossamer:own (%make-keypair sk (%pubkey-of-fixed sk)) sk))
        (error () nil)))))          ; 0 or >= n: astronomically rare, draw again

(defun make-keypair (&optional secret)
  "Generate a keypair, or rebuild one from SECRET (32 bytes / hex)."
  (if secret (keypair-from-secret secret) (generate-keypair)))

(defun keypair-wipe (keypair)
  "Wipe KEYPAIR's secret and return its buffer to the pool.  The secret becomes NIL:
the buffer may next hold another key, so nothing may keep using it."
  (when (keypair-secret-key keypair)
    (gossamer:disown keypair)
    (gossamer:free (keypair-secret-key keypair))
    (setf (keypair-secret-key keypair) nil))
  keypair)

(defun secret-hex (keypair)
  "Lowercase hex of the secret key -- an explicit EXPORT of the secret onto the heap
(for writing a key file, showing an nsec).  Handle with care."
  (u:bytes->hex (secret-key-of keypair)))

(defun public-hex (keypair)
  "Lowercase hex of the x-only public key (this is the event \"pubkey\")."
  (u:bytes->hex (keypair-public-key keypair)))

(defun sign (keypair message32)
  "BIP340-sign a 32-byte MESSAGE (hex or bytes) with KEYPAIR (or a fixed secret);
returns 64 signature bytes.  Safe to call from several threads at once."
  (let ((sk (secret-key-of keypair))
        (m (u:->bytes32 message32))
        (aux (make-array 32 :element-type '(unsigned-byte 8))))
    (natrium:random-bytes-into aux)            ; BIP-340 auxiliary randomness
    (bt:with-lock-held (*curve-lock*) (sch:schnorr-sign sk m aux))))

(defun verify (public-key message32 sig64)
  "T iff SIG64 is a valid signature of MESSAGE32 under x-only PUBLIC-KEY.
All args may be hex or bytes.  Safe to call from several threads at once."
  (let ((pk (u:->bytes32 public-key))
        (m (u:->bytes32 message32))
        (sig (coerce (if (stringp sig64) (u:hex->bytes sig64) sig64)
                     '(vector (unsigned-byte 8)))))
    (bt:with-lock-held (*curve-lock*) (sch:schnorr-verify pk m sig))))

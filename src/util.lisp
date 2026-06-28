;;;; src/util.lisp — small shared helpers: hex, UTF-8, SHA-256, randomness.

(in-package #:cl-nostr.util)

(deftype octets () '(simple-array (unsigned-byte 8) (*)))

(declaim (inline octets))
(defun octets (n &key (initial-element 0))
  "A fresh (unsigned-byte 8) simple-array of length N."
  (make-array n :element-type '(unsigned-byte 8) :initial-element initial-element))

(defun bytes->hex (bytes)
  "Lowercase hex string for a byte sequence."
  (let ((s (make-string (* 2 (length bytes)))))
    (loop for b across bytes
          for i from 0 by 2
          do (let ((hi (ldb (byte 4 4) b)) (lo (ldb (byte 4 0) b)))
               (setf (char s i) (digit-char hi 16)
                     (char s (1+ i)) (digit-char lo 16))))
    (string-downcase s)))

(defun hex->bytes (hex)
  "Byte vector for an even-length hex string."
  (let* ((len (length hex)))
    (when (oddp len) (error "hex->bytes: odd-length hex string"))
    (let ((out (octets (floor len 2))))
      (loop for i from 0 below len by 2
            for j from 0
            do (setf (aref out j)
                     (logior (ash (digit-char-p (char hex i) 16) 4)
                             (digit-char-p (char hex (1+ i)) 16))))
      out)))

(defun ->bytes32 (thing)
  "Coerce a 32-byte value given as a hex string or a byte vector to (unsigned-byte 8) (32)."
  (let ((b (etypecase thing
             (string (hex->bytes thing))
             (sequence (coerce thing '(vector (unsigned-byte 8)))))))
    (unless (= (length b) 32) (error "expected 32 bytes, got ~d" (length b)))
    b))

(defun string->utf8 (string)
  "UTF-8 encode STRING to bytes."
  (sb-ext:string-to-octets string :external-format :utf-8))

(defun utf8->string (bytes)
  "Decode UTF-8 BYTES to a string."
  (sb-ext:octets-to-string (coerce bytes '(vector (unsigned-byte 8)))
                           :external-format :utf-8))

(defun sha256 (bytes)
  "SHA-256 digest (32 bytes) of a byte sequence."
  (ironclad:digest-sequence :sha256 (coerce bytes '(vector (unsigned-byte 8)))))

(defun random-bytes (n)
  "N cryptographically-strong random bytes."
  (ironclad:random-data n))

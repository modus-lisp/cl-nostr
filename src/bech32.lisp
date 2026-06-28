;;;; src/bech32.lisp — NIP-19 bech32-encoded entities.
;;;;
;;;; Nostr uses plain bech32 (checksum constant 1, BIP173 — *not* bech32m) but
;;;; without the 90-char limit, since TLV entities can be long.  Two families:
;;;;
;;;;   simple : npub / nsec / note  — the bech32 of 32 raw bytes.
;;;;   TLV    : nprofile / nevent / naddr — a list of (type length value) records.
;;;;
;;;; TLV types (NIP-19): 0 = special (pubkey/id/identifier), 1 = relay (ascii,
;;;; repeatable), 2 = author pubkey (32 bytes), 3 = kind (4-byte big-endian uint).

(in-package #:cl-nostr.bech32)

(defparameter +charset+ "qpzry9x8gf2tvdw0s3jn54khce6mua7l")
(defparameter +const+ 1)                 ; bech32 (BIP173); bech32m would be #x2bc830a3

(defun %polymod (values)
  (let ((gen #(#x3b6a57b2 #x26508e6d #x1ea119fa #x3d4233dd #x2a1462b3))
        (chk 1))
    (dolist (v values chk)
      (let ((top (ash chk -25)))
        (setf chk (logand (logxor (ash (logand chk #x1ffffff) 5) v) #xffffffff))
        (dotimes (i 5)
          (when (logbitp i top)
            (setf chk (logxor chk (aref gen i)))))))))

(defun %hrp-expand (hrp)
  (append (loop for c across hrp collect (ash (char-code c) -5))
          (list 0)
          (loop for c across hrp collect (logand (char-code c) 31))))

(defun %checksum (hrp data)
  (let* ((vals (append (%hrp-expand hrp) data (list 0 0 0 0 0 0)))
         (pm (logxor (%polymod vals) +const+)))
    (loop for i from 0 below 6 collect (logand (ash pm (* -5 (- 5 i))) 31))))

(defun %convert-bits (data from to pad)
  "Regroup DATA's elements from FROM-bit groups into TO-bit groups."
  (let ((acc 0) (bits 0) (out '()) (maxv (1- (ash 1 to))))
    (loop for value across data do
      (setf acc (logior (ash acc from) value)
            bits (+ bits from))
      (loop while (>= bits to) do
        (decf bits to)
        (push (logand (ash acc (- bits)) maxv) out)))
    (when pad
      (when (plusp bits)
        (push (logand (ash acc (- to bits)) maxv) out)))
    (nreverse out)))

(defun encode (hrp bytes)
  "bech32-encode BYTES (an 8-bit sequence) under HRP."
  (let* ((data (%convert-bits (coerce bytes 'vector) 8 5 t))
         (full (append data (%checksum hrp data))))
    (concatenate 'string hrp "1"
                 (map 'string (lambda (v) (char +charset+ v)) full))))

(defun decode (string)
  "Decode a bech32 STRING -> (values hrp bytes).  Verifies the checksum."
  (let* ((s (string-downcase string))
         (pos (position #\1 s :from-end t)))
    (unless (and pos (>= pos 1) (<= (+ pos 7) (length s)))
      (error "bech32: bad layout"))
    (let* ((hrp (subseq s 0 pos))
           (data (loop for i from (1+ pos) below (length s)
                       for v = (position (char s i) +charset+)
                       do (unless v (error "bech32: bad char ~c" (char s i)))
                       collect v)))
      (unless (= (%polymod (append (%hrp-expand hrp) data)) +const+)
        (error "bech32: bad checksum"))
      (let ((payload (subseq data 0 (- (length data) 6))))
        (values hrp
                (coerce (%convert-bits (coerce payload 'vector) 5 8 nil)
                        '(vector (unsigned-byte 8))))))))

;;; ---- simple entities ------------------------------------------------------

(defun %simple-encode (hrp thing) (encode hrp (u:->bytes32 thing)))
(defun %simple-decode (hrp string)
  (multiple-value-bind (got bytes) (decode string)
    (unless (string= got hrp) (error "expected ~a, got ~a" hrp got))
    bytes))

(defun npub-encode (pubkey) (%simple-encode "npub" pubkey))
(defun npub-decode (s) (%simple-decode "npub" s))
(defun nsec-encode (secret) (%simple-encode "nsec" secret))
(defun nsec-decode (s) (%simple-decode "nsec" s))
(defun note-encode (id) (%simple-encode "note" id))
(defun note-decode (s) (%simple-decode "note" s))

;;; ---- TLV entities ---------------------------------------------------------

(defun %tlv-encode (hrp records)
  "RECORDS is a list of (type . value-bytes).  Concatenate as type/len/value."
  (let ((out '()))
    (dolist (rec records)
      (let* ((type (car rec))
             (val (coerce (cdr rec) '(vector (unsigned-byte 8))))
             (len (length val)))
        (when (> len 255) (error "TLV value too long"))
        (push type out) (push len out)
        (loop for b across val do (push b out))))
    (encode hrp (coerce (nreverse out) '(vector (unsigned-byte 8))))))

(defun %tlv-decode (hrp string)
  "Decode to a list of (type . value-bytes) in stream order."
  (multiple-value-bind (got bytes) (decode string)
    (unless (string= got hrp) (error "expected ~a, got ~a" hrp got))
    (loop with i = 0 with n = (length bytes) with recs = '()
          while (< (+ i 2) (1+ n))
          do (let* ((type (aref bytes i))
                    (len (aref bytes (1+ i)))
                    (val (subseq bytes (+ i 2) (+ i 2 len))))
               (push (cons type val) recs)
               (incf i (+ 2 len)))
          finally (return (nreverse recs)))))

(defun %kind->bytes (kind)
  (let ((b (u:octets 4)))
    (loop for i from 0 below 4 do (setf (aref b i) (ldb (byte 8 (* 8 (- 3 i))) kind)))
    b))
;; small local big-endian helper (kept here to avoid leaking into util's API)
(defun %be (bytes) (let ((n 0)) (loop for b across bytes do (setf n (logior (ash n 8) b))) n))

(defun nprofile-encode (pubkey &key relays)
  "TLV nprofile from a 32-byte PUBKEY and optional RELAYS (list of url strings)."
  (%tlv-encode "nprofile"
    (list* (cons 0 (u:->bytes32 pubkey))
           (mapcar (lambda (r) (cons 1 (u:string->utf8 r))) relays))))

(defun nprofile-decode (string)
  "-> (values pubkey-bytes relays)."
  (let ((recs (%tlv-decode "nprofile" string)) pk relays)
    (dolist (r recs)
      (case (car r)
        (0 (setf pk (cdr r)))
        (1 (push (u:utf8->string (cdr r)) relays))))
    (values pk (nreverse relays))))

(defun nevent-encode (id &key relays author kind)
  "TLV nevent from a 32-byte event ID, optional RELAYS, AUTHOR pubkey, KIND."
  (%tlv-encode "nevent"
    (append (list (cons 0 (u:->bytes32 id)))
            (mapcar (lambda (r) (cons 1 (u:string->utf8 r))) relays)
            (when author (list (cons 2 (u:->bytes32 author))))
            (when kind (list (cons 3 (%kind->bytes kind)))))))

(defun nevent-decode (string)
  "-> (values id-bytes relays author-bytes kind)."
  (let ((recs (%tlv-decode "nevent" string)) id relays author kind)
    (dolist (r recs)
      (case (car r)
        (0 (setf id (cdr r)))
        (1 (push (u:utf8->string (cdr r)) relays))
        (2 (setf author (cdr r)))
        (3 (setf kind (%be (cdr r))))))
    (values id (nreverse relays) author kind)))

(defun naddr-encode (identifier author kind &key relays)
  "TLV naddr for a replaceable event: IDENTIFIER (d-tag string), AUTHOR pubkey, KIND."
  (%tlv-encode "naddr"
    (append (list (cons 0 (u:string->utf8 identifier)))
            (mapcar (lambda (r) (cons 1 (u:string->utf8 r))) relays)
            (list (cons 2 (u:->bytes32 author)))
            (list (cons 3 (%kind->bytes kind))))))

(defun naddr-decode (string)
  "-> (values identifier author-bytes kind relays)."
  (let ((recs (%tlv-decode "naddr" string)) id relays author kind)
    (dolist (r recs)
      (case (car r)
        (0 (setf id (u:utf8->string (cdr r))))
        (1 (push (u:utf8->string (cdr r)) relays))
        (2 (setf author (cdr r)))
        (3 (setf kind (%be (cdr r))))))
    (values id author kind (nreverse relays))))

(defun decode-entity (string)
  "Decode any nostr bech32 STRING, dispatching on its HRP.
Returns (values kind plist) where KIND is one of
:npub :nsec :note :nprofile :nevent :naddr and PLIST holds the fields."
  (let ((hrp (string-downcase (subseq string 0 (position #\1 string)))))
    (cond
      ((string= hrp "npub") (values :npub (list :pubkey (npub-decode string))))
      ((string= hrp "nsec") (values :nsec (list :secret (nsec-decode string))))
      ((string= hrp "note") (values :note (list :id (note-decode string))))
      ((string= hrp "nprofile")
       (multiple-value-bind (pk relays) (nprofile-decode string)
         (values :nprofile (list :pubkey pk :relays relays))))
      ((string= hrp "nevent")
       (multiple-value-bind (id relays author kind) (nevent-decode string)
         (values :nevent (list :id id :relays relays :author author :kind kind))))
      ((string= hrp "naddr")
       (multiple-value-bind (id author kind relays) (naddr-decode string)
         (values :naddr (list :identifier id :author author :kind kind :relays relays))))
      (t (error "unknown nostr entity hrp: ~a" hrp)))))

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

;;; ---- deadlines -----------------------------------------------------------
;;; Nothing in a network client may be unbounded.  An HTTP library's read-timeout
;;; bounds one read, not the whole request: a server that trickles a byte a second
;;; never trips it, and the call never returns.  So the only reliable bound is an
;;; outside one — run the work in its own thread and abandon it on the clock.

(defun call-with-deadline (seconds thunk &key (name "cl-nostr deadline"))
  "Call THUNK, giving up after SECONDS (NIL = no deadline).  Returns four values:
THUNK's primary value, the SERIOUS-CONDITION it signalled (or NIL), T if it ran out
of time, and the elapsed seconds.  Never signals: a caller inspects the values."
  (let ((start (get-internal-real-time)))
    (flet ((elapsed ()
             (/ (float (- (get-internal-real-time) start))
                internal-time-units-per-second)))
      (if (null seconds)
          (handler-case (values (funcall thunk) nil nil (elapsed))
            (serious-condition (c) (values nil c nil (elapsed))))
          (let* ((box (list nil nil nil))   ; (done value condition)
                 (thread (bt:make-thread
                          (lambda ()
                            (unwind-protect
                                 (handler-case (setf (second box) (funcall thunk))
                                   (serious-condition (c) (setf (third box) c)))
                              (setf (first box) t)))
                          :name name)))
            (loop with waited = 0.0 with step = 0.05
                  until (first box) while (< waited seconds)
                  do (sleep step) (incf waited step))
            (cond ((first box) (values (second box) (third box) nil (elapsed)))
                  (t (ignore-errors (bt:destroy-thread thread))
                     (values nil nil t (elapsed)))))))))

(defmacro with-deadline ((seconds &key (name "cl-nostr deadline")) &body body)
  "Run BODY under CALL-WITH-DEADLINE; see it for the four returned values."
  `(call-with-deadline ,seconds (lambda () ,@body) :name ,name))

(defun call-in-parallel (seconds thunks &key (name "cl-nostr parallel"))
  "Run every thunk in THUNKS at once, each in its own thread, waiting at most
SECONDS for the slowest and abandoning the rest.  Returns one
(VALUE CONDITION TIMED-OUT-P ELAPSED) list per thunk, in THUNKS order.  Never signals."
  (let* ((start (get-internal-real-time))
         (boxes (loop repeat (length thunks) collect (list nil nil nil 0.0)))
         (threads (loop for thunk in thunks
                        for box in boxes
                        for i from 0
                        collect (let ((thunk thunk) (box box)
                                      (began (get-internal-real-time)))
                                  (bt:make-thread
                                   (lambda ()
                                     (unwind-protect
                                          (handler-case (setf (second box) (funcall thunk))
                                            (serious-condition (c) (setf (third box) c)))
                                       (setf (fourth box)
                                             (/ (float (- (get-internal-real-time) began))
                                                internal-time-units-per-second)
                                             (first box) t)))
                                   :name (format nil "~a ~d" name i))))))
    (loop with waited = 0.0 with step = 0.05
          until (every #'first boxes) while (< waited (or seconds 0))
          do (sleep step) (incf waited step))
    (loop for box in boxes
          for thread in threads
          unless (first box)
            do (ignore-errors (bt:destroy-thread thread)))
    (loop for box in boxes
          collect (if (first box)
                      (list (second box) (third box) nil (fourth box))
                      (list nil nil t (/ (float (- (get-internal-real-time) start))
                                         internal-time-units-per-second))))))

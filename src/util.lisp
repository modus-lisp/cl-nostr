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
  #+sbcl (sb-ext:string-to-octets string :external-format :utf-8)
  #-sbcl
  (let ((out (make-array (* 4 (length string)) :element-type '(unsigned-byte 8)))
        (n 0))
    (flet ((put (b) (setf (aref out n) b) (incf n)))
      (loop for ch across string
            for c = (char-code ch)
            do (cond ((< c #x80) (put c))
                     ((< c #x800)
                      (put (logior #xC0 (ash c -6)))
                      (put (logior #x80 (logand c #x3F))))
                     ((< c #x10000)
                      (put (logior #xE0 (ash c -12)))
                      (put (logior #x80 (logand (ash c -6) #x3F)))
                      (put (logior #x80 (logand c #x3F))))
                     (t
                      (put (logior #xF0 (ash c -18)))
                      (put (logior #x80 (logand (ash c -12) #x3F)))
                      (put (logior #x80 (logand (ash c -6) #x3F)))
                      (put (logior #x80 (logand c #x3F)))))))
    (subseq out 0 n)))

(defun utf8->string (bytes)
  "Decode UTF-8 BYTES to a string."
  #+sbcl (sb-ext:octets-to-string (coerce bytes '(vector (unsigned-byte 8)))
                                  :external-format :utf-8)
  #-sbcl
  (let ((out (make-string (length bytes))) (n 0) (i 0) (len (length bytes)))
    (flet ((cont (k) (if (< (+ i k) len) (logand (elt bytes (+ i k)) #x3F)
                         (error "utf8->string: truncated UTF-8 sequence"))))
      (loop while (< i len)
            do (let* ((b (elt bytes i))
                      (k (cond ((< b #x80) 0) ((< b #xE0) 1) ((< b #xF0) 2) (t 3)))
                      (c (case k
                           (0 b)
                           (1 (logior (ash (logand b #x1F) 6) (cont 1)))
                           (2 (logior (ash (logand b #x0F) 12) (ash (cont 1) 6) (cont 2)))
                           (t (logior (ash (logand b #x07) 18) (ash (cont 1) 12)
                                      (ash (cont 2) 6) (cont 3))))))
                 (setf (char out n) (code-char c))
                 (incf n)
                 (incf i (1+ k)))))
    (subseq out 0 n)))

(defun sha256 (bytes)
  "SHA-256 digest (32 bytes) of a byte sequence."
  (natrium:sha256 (coerce bytes '(simple-array (unsigned-byte 8) (*)))))

(defun random-bytes (n)
  "N cryptographically-strong random bytes."
  (natrium:random-bytes n))

;;; ---- deadlines -----------------------------------------------------------
;;; Nothing in a network client may be unbounded.  An HTTP library's read-timeout
;;; bounds one read, not the whole request: a server that trickles a byte a second
;;; never trips it, and the call never returns.  So the only reliable bound is an
;;; outside one — run the work in its own thread and abandon it on the clock.

;;; ---- waiting -------------------------------------------------------------
;;; Every loop below that waits for something another party will deliver calls
;;; WAIT-STEP rather than SLEEP.  Where each relay has a reader thread (SBCL),
;;; delivery happens by itself and waiting is sleeping.  Where it cannot -- modus,
;;; whose threads share no state, so a relay's connection belongs to the one
;;; thread that drives it -- cl-nostr.relay installs its PUMP here, and waiting
;;; is servicing the relays.

(defvar *pump* nil
  "A function of SECONDS that services connections for that long, or NIL to sleep.")

(defun wait-step (seconds)
  "Wait SECONDS while whatever is being waited for is delivered."
  (if *pump* (funcall *pump* seconds) (sleep seconds)))

#+modus
(progn
  ;; MODUS: a thread's objects belong to it, and storing one where another thread
  ;; can see it is refused -- so the worker cannot fill in a shared BOX.  It hands
  ;; its result back as its RETURN VALUE, which JOIN-THREAD copies across.  A
  ;; condition comes back as its text.  A thread modus cannot stop (it has no
  ;; TERMINATE-THREAD) runs on after its deadline; only its answer is abandoned.
  (defun %deadline-run (thunk)
    (let ((began (get-internal-real-time)))
      (flet ((elapsed () (/ (float (- (get-internal-real-time) began))
                            internal-time-units-per-second)))
        (handler-case (list :ok (funcall thunk) (elapsed))
          (serious-condition (c)
            (list :err (or (ignore-errors (princ-to-string c)) "an error") (elapsed)))))))

  (defun %deadline-unpack (thread)
    "(VALUE CONDITION ELAPSED) from a finished THREAD running %DEADLINE-RUN."
    (let ((r (handler-case (bt:join-thread thread)
               (error (e) (list :err (or (ignore-errors (princ-to-string e)) "an error") 0.0)))))
      (if (eq (first r) :ok)
          (list (second r) nil (third r))
          (list nil (make-condition 'simple-error :format-control "~a"
                                                  :format-arguments (list (second r)))
                (third r))))))

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
          #+modus
          (let ((thread (bt:make-thread (lambda () (%deadline-run thunk)) :name name)))
            (loop with waited = 0.0 with step = 0.05
                  while (bt:thread-alive-p thread) while (< waited seconds)
                  do (wait-step step) (incf waited step))
            (if (bt:thread-alive-p thread)
                (values nil nil t (elapsed))
                (destructuring-bind (value condition ran) (%deadline-unpack thread)
                  (declare (ignore ran))
                  (values value condition nil (elapsed)))))
          #-modus
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
                  do (wait-step step) (incf waited step))
            (cond ((first box) (values (second box) (third box) nil (elapsed)))
                  (t (ignore-errors (bt:destroy-thread thread))
                     (values nil nil t (elapsed)))))))))

(defmacro with-deadline ((seconds &key (name "cl-nostr deadline")) &body body)
  "Run BODY under CALL-WITH-DEADLINE; see it for the four returned values."
  `(call-with-deadline ,seconds (lambda () ,@body) :name ,name))

#+modus
(defun call-in-parallel (seconds thunks &key (name "cl-nostr parallel"))
  "See the portable definition below: the same contract, the results returned by
each thread rather than written into shared boxes."
  (let* ((start (get-internal-real-time))
         (threads (loop for thunk in thunks for i from 0
                        collect (let ((thunk thunk))
                                  (bt:make-thread (lambda () (%deadline-run thunk))
                                                  :name (format nil "~a ~d" name i))))))
    (loop with waited = 0.0 with step = 0.05
          while (some #'bt:thread-alive-p threads) while (< waited (or seconds 0))
          do (wait-step step) (incf waited step))
    (loop for thread in threads
          collect (if (bt:thread-alive-p thread)
                      (list nil nil t (/ (float (- (get-internal-real-time) start))
                                         internal-time-units-per-second))
                      (destructuring-bind (value condition ran) (%deadline-unpack thread)
                        (list value condition nil ran))))))

#-modus
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
          do (wait-step step) (incf waited step))
    (loop for box in boxes
          for thread in threads
          unless (first box)
            do (ignore-errors (bt:destroy-thread thread)))
    (loop for box in boxes
          collect (if (first box)
                      (list (second box) (third box) nil (fourth box))
                      (list nil nil t (/ (float (- (get-internal-real-time) start))
                                         internal-time-units-per-second))))))

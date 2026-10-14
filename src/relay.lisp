;;;; src/relay.lisp — one relay connection.
;;;;
;;;; A relay speaks NIP-01 over a single WebSocket.  Client -> relay messages:
;;;;   ["EVENT", <event>]            publish
;;;;   ["REQ", <subid>, <filter>...] open a subscription
;;;;   ["CLOSE", <subid>]            close it
;;;; Relay -> client:
;;;;   ["EVENT", <subid>, <event>]   a matching event
;;;;   ["EOSE", <subid>]             end of stored events (now live)
;;;;   ["OK", <id>, <bool>, <msg>]   publish accepted/rejected
;;;;   ["NOTICE", <msg>]             human-readable notice
;;;;   ["CLOSED", <subid>, <msg>]    subscription closed by the relay
;;;;
;;;; seal.websocket is blocking, so each relay owns a read thread that pumps
;;;; frames into %DISPATCH.  Every dispatch therefore happens off that thread;
;;;; the lock guards the subscription / pending-OK tables.
;;;;
;;;; ON MODUS there is no read thread.  Modus threads share no state: a relay's
;;;; WebSocket and TLS session may only be touched by the thread that owns them,
;;;; and every object a reader thread made would be refused where the caller could
;;;; see it.  So one thread drives every relay by readiness (seal's PENDING-P and
;;;; RECEIVE :WAIT NIL): PUMP reads whatever has arrived and dispatches it, with the
;;;; callbacks on the calling thread, and every wait in cl-nostr (WAIT-STEP) pumps.
;;;; An application's own loop calls PUMP; on SBCL PUMP just waits.

(in-package #:cl-nostr.relay)

(defstruct subscription
  (id nil :type string)
  (filters nil :type list)
  (on-event nil)
  (on-eose nil))

(defstruct (relay (:constructor %make-relay))
  (url nil :type string)
  (client nil)
  (connected-p nil)
  (subs (make-hash-table :test 'equal))     ; subid -> subscription
  (pending-ok (make-hash-table :test 'equal)) ; event-id -> (lambda (accepted msg))
  (notice-handler nil)
  (reader nil)                              ; the thread pumping frames into %DISPATCH
  (lock (bt:make-lock "relay")))

(defun %random-id ()
  (cl-nostr.util:bytes->hex (cl-nostr.util:random-bytes 8)))

;;; ---- message dispatch ----------------------------------------------------

(defun %as-bool (x) (and x t))           ; json-simple parses JSON true/false to T/NIL

(defun %dispatch (relay text)
  (let ((msg (ignore-errors (json-simple:parse text))))
    (when (and msg (vectorp msg) (plusp (length msg)))
      (let ((type (aref msg 0)))
        (cond
          ((string= type "EVENT")
           (let* ((subid (aref msg 1))
                  (event (cl-nostr.event:json->event (aref msg 2)))
                  (sub (bt:with-lock-held ((relay-lock relay))
                         (gethash subid (relay-subs relay)))))
             (when (and sub (subscription-on-event sub))
               (funcall (subscription-on-event sub) event relay))))
          ((string= type "EOSE")
           (let* ((subid (aref msg 1))
                  (sub (bt:with-lock-held ((relay-lock relay))
                         (gethash subid (relay-subs relay)))))
             (when (and sub (subscription-on-eose sub))
               (funcall (subscription-on-eose sub) relay))))
          ((string= type "OK")
           (let* ((id (aref msg 1))
                  (accepted (%as-bool (and (> (length msg) 2) (aref msg 2))))
                  (note (and (> (length msg) 3) (aref msg 3)))
                  (cb (bt:with-lock-held ((relay-lock relay))
                        (prog1 (gethash id (relay-pending-ok relay))
                          (remhash id (relay-pending-ok relay))))))
             (when cb (funcall cb accepted note))))
          ((string= type "NOTICE")
           (when (relay-notice-handler relay)
             (funcall (relay-notice-handler relay) (and (> (length msg) 1) (aref msg 1)))))
          ((string= type "CLOSED")
           (let ((subid (aref msg 1)))
             (bt:with-lock-held ((relay-lock relay))
               (remhash subid (relay-subs relay))))))))))

;;; ---- the pump (modus) -----------------------------------------------------

(defvar *open-relays* '()
  "Relays this process has connected and not closed: what PUMP services.")
(defvar *open-relays-lock* (bt:make-lock "cl-nostr open relays"))
(defvar *pump-hooks* '()
  "Functions of no arguments PUMP calls once per call (a pool's keepalive sweep).")

#+(and modus seal-readiness)
(defun %pump-relay (relay)
  "Read and dispatch every message RELAY has ready.  The number handled."
  (let ((ws (relay-client relay)) (n 0))
    (when (relay-connected-p relay)
      (handler-case
          (loop
            (multiple-value-bind (text state) (seal.websocket:receive-text ws :wait nil)
              (cond (text (handler-case (%dispatch relay text) (error () nil))
                          (incf n))
                    ((eq state :pending) (return))
                    (t (setf (relay-connected-p relay) nil) (return)))))
        (error () (setf (relay-connected-p relay) nil))))
    n))

(defun pump (&optional (timeout 0))
  "Service every open relay for up to TIMEOUT seconds: read each message that has
arrived and dispatch it, running the callbacks on THIS thread.  Returns how many
were handled.  Where each relay has a reader thread of its own (SBCL), messages
arrive by themselves and this only waits -- so code that calls PUMP in its loop is
portable."
  #-(and modus seal-readiness)
  (progn (when (plusp timeout) (sleep timeout)) 0)
  #+(and modus seal-readiness)
  (let ((end (+ (get-internal-real-time)
                (round (* timeout internal-time-units-per-second))))
        (n 0))
    (dolist (hook *pump-hooks*) (ignore-errors (funcall hook)))
    (loop
      (let ((got 0))
        (dolist (relay (bt:with-lock-held (*open-relays-lock*) (copy-list *open-relays*)))
          (incf got (%pump-relay relay)))
        (incf n got)
        (when (>= (get-internal-real-time) end) (return n))
        (when (zerop got) (sleep 0.005))))))

#+(and modus seal-readiness)
(setf cl-nostr.util::*pump* #'pump)

;;; ---- connect / send ------------------------------------------------------

(defun connect-relay (url &key on-notice (verify t) (timeout 10))
  "Open a relay at URL (ws:// or wss://).  Blocks until connected or errors.
ON-NOTICE, if given, is called with each NOTICE message string.

seal.websocket is a blocking client, where websocket-driver was event-driven with
a read thread of its own — so the thread is ours now.  That is the whole of the
difference, and it is worth it: websocket-driver reaches cl+ssl for wss://, i.e.
OpenSSL through an FFI, in a library whose point is that the crypto is Lisp."
  (let* ((ws (seal.websocket:connect url :verify verify :timeout timeout))
         (relay (%make-relay :url url :client ws :notice-handler on-notice)))
    (setf (relay-connected-p relay) t)
    #+(and modus seal-readiness)
    (bt:with-lock-held (*open-relays-lock*) (push relay *open-relays*))
    #-(and modus seal-readiness)
    (setf (relay-reader relay)
          (bt:make-thread
           (lambda ()
             (unwind-protect
                  (loop for text = (handler-case (seal.websocket:receive-text ws)
                                     (error () nil))
                        while text
                        do (handler-case (%dispatch relay text)
                             ;; One malformed message must not take the relay down.
                             (error () nil)))
               (setf (relay-connected-p relay) nil)))
           :name (format nil "cl-nostr relay ~a" url)))
    relay))

(defun %send (relay string)
  (unless (relay-connected-p relay) (error "relay not connected: ~a" (relay-url relay)))
  (seal.websocket:send-text (relay-client relay) string))

(defun close-relay (relay)
  "Close the relay's WebSocket."
  (ignore-errors (seal.websocket:close-socket (relay-client relay)))
  (setf (relay-connected-p relay) nil)
  (bt:with-lock-held (*open-relays-lock*)
    (setf *open-relays* (remove relay *open-relays*)))
  (let ((th (relay-reader relay)))
    (when (and th (bt:thread-alive-p th))
      (ignore-errors (bt:join-thread th :timeout 2))))
  relay)

(defun relay-ping (relay)
  "Send a WebSocket ping — relays close idle sockets, so a periodic ping keeps a
long-lived subscription alive.  A failure marks the relay disconnected (so a pool
watcher can reconnect it)."
  (when (relay-connected-p relay)
    (handler-case (progn (seal.websocket:send-ping (relay-client relay)) t)
      (error () (setf (relay-connected-p relay) nil) nil))))

;;; ---- publish / subscribe -------------------------------------------------

(defun publish (relay event &key on-ok)
  "Send EVENT to the relay.  ON-OK, if given, is called as (accepted-p message)
when the relay replies with OK for this event id."
  (when on-ok
    (bt:with-lock-held ((relay-lock relay))
      (setf (gethash (cl-nostr.event:event-id event) (relay-pending-ok relay)) on-ok)))
  (%send relay (concatenate 'string "[\"EVENT\"," (cl-nostr.event:event->json event) "]"))
  (cl-nostr.event:event-id event))

(defun subscribe (relay filters &key on-event on-eose id)
  "Open a subscription for FILTERS (a single filter or a list).  ON-EVENT is
called (event relay) per matching event; ON-EOSE (relay) at end of stored events.
Returns the subscription."
  (let* ((filters (if (listp filters) filters (list filters)))
         (subid (or id (%random-id)))
         (sub (make-subscription :id subid :filters filters
                                 :on-event on-event :on-eose on-eose)))
    (bt:with-lock-held ((relay-lock relay))
      (setf (gethash subid (relay-subs relay)) sub))
    (%send relay
           (with-output-to-string (out)
             (format out "[\"REQ\",~s" subid)
             (dolist (f filters)
               (write-char #\, out)
               (write-string (cl-nostr.filter:filter->json f) out))
             (write-char #\] out)))
    sub))

(defun unsubscribe (relay subscription-or-id)
  "Close a subscription (by object or subid string)."
  (let ((subid (if (subscription-p subscription-or-id)
                   (subscription-id subscription-or-id)
                   subscription-or-id)))
    (bt:with-lock-held ((relay-lock relay))
      (remhash subid (relay-subs relay)))
    (ignore-errors (%send relay (format nil "[\"CLOSE\",~s]" subid)))
    subid))

;;; thin re-exports so callers can set handlers after connecting
(defun on-event (sub fn) (setf (subscription-on-event sub) fn))
(defun on-eose (sub fn) (setf (subscription-on-eose sub) fn))
(defun on-notice (relay fn) (setf (relay-notice-handler relay) fn))
(defun on-ok (relay event-id fn)
  (bt:with-lock-held ((relay-lock relay))
    (setf (gethash event-id (relay-pending-ok relay)) fn)))

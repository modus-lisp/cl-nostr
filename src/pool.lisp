;;;; src/pool.lisp — a pool of relays: the high-level client surface.
;;;;
;;;; Nostr's redundancy model is "publish to many relays, read from many relays."
;;;; A pool fans publish/subscribe out to all its relays and (for fetch-events)
;;;; deduplicates the merged stream by event id, so the same note arriving from
;;;; three relays is delivered once.

(in-package #:cl-nostr.pool)

(defstruct (pool (:constructor %make-pool))
  (relays '() :type list)
  (lock (bt:make-lock "pool")))

(defun %connect-with-timeout (url verify on-notice timeout)
  "Connect to URL, abandoning the attempt after TIMEOUT seconds (websocket-driver's
handshake is synchronous and otherwise unbounded).  Returns the relay or NIL."
  (let ((box (list nil nil)))           ; (done? . relay)
    (let ((th (bt:make-thread
               (lambda ()
                 (let ((relay (ignore-errors
                               (r:connect-relay url :verify verify :on-notice on-notice))))
                   (setf (second box) relay (first box) t)))
               :name (format nil "cl-nostr connect ~a" url))))
      (loop with waited = 0.0 with step = 0.1
            until (first box) while (< waited timeout)
            do (sleep step) (incf waited step))
      (unless (first box) (ignore-errors (bt:destroy-thread th)))
      (second box))))

(defun make-pool (&optional urls &key (verify t) (timeout 10))
  "Make a pool, connecting (in parallel) to a list of relay URLS up front."
  (let* ((pool (%make-pool))
         (urls (remove nil (if (listp urls) urls (list urls))))
         (results (make-array (length urls) :initial-element nil))
         (threads (loop for url in urls for i from 0
                        collect (let ((i i) (url url))
                                  (bt:make-thread
                                   (lambda ()
                                     (setf (aref results i)
                                           (%connect-with-timeout url verify nil timeout)))
                                   :name (format nil "cl-nostr pool ~a" url))))))
    (dolist (th threads) (ignore-errors (bt:join-thread th)))
    (loop for relay across results when relay do (push relay (pool-relays pool)))
    pool))

(defun add-relay (pool url &key (verify t) on-notice (timeout 10))
  "Connect to URL and add it to the pool.  Returns the relay (or NIL on failure)."
  (let ((relay (%connect-with-timeout url verify on-notice timeout)))
    (when relay
      (bt:with-lock-held ((pool-lock pool))
        (push relay (pool-relays pool))))
    relay))

(defun remove-relay (pool relay-or-url)
  "Close and drop a relay (by object or url)."
  (bt:with-lock-held ((pool-lock pool))
    (let ((relay (if (stringp relay-or-url)
                     (find relay-or-url (pool-relays pool) :key #'r:relay-url :test #'string=)
                     relay-or-url)))
      (when relay
        (r:close-relay relay)
        (setf (pool-relays pool) (remove relay (pool-relays pool)))))))

(defun close-pool (pool)
  "Close every relay in the pool."
  (bt:with-lock-held ((pool-lock pool))
    (mapc #'r:close-relay (pool-relays pool))
    (setf (pool-relays pool) '()))
  pool)

(defun %relays (pool)
  (bt:with-lock-held ((pool-lock pool)) (copy-list (pool-relays pool))))

(defun pool-publish (pool event &key on-ok)
  "Publish EVENT to every connected relay.  ON-OK, if given, is called as
(relay accepted-p message) once per relay reply."
  (dolist (relay (%relays pool) (cl-nostr.event:event-id event))
    (ignore-errors
     (r:publish relay event
                :on-ok (when on-ok
                         (lambda (accepted msg) (funcall on-ok relay accepted msg)))))))

(defun pool-subscribe (pool filters &key on-event on-eose)
  "Subscribe across every relay, de-duplicating events by id.  ON-EVENT is called
(event relay) once per distinct event; ON-EOSE (relay) as each relay finishes its
stored set.  Returns the list of per-relay subscriptions."
  (let ((seen (make-hash-table :test 'equal))
        (seen-lock (bt:make-lock "seen")))
    (flet ((dedup (event relay)
             (when on-event
               (let ((id (cl-nostr.event:event-id event)))
                 (when (bt:with-lock-held (seen-lock)
                         (unless (gethash id seen) (setf (gethash id seen) t)))
                   (funcall on-event event relay))))))
      (loop for relay in (%relays pool)
            collect (r:subscribe relay filters :on-event #'dedup :on-eose on-eose)))))

(defun fetch-events (pool filters &key (timeout 5) limit)
  "Collect stored events matching FILTERS from all relays, blocking until every
relay sends EOSE or TIMEOUT seconds pass.  Deduplicated by id, newest first.
LIMIT caps the returned count."
  (let* ((relays (%relays pool))
         (n (length relays))
         (results '())
         (eose 0)
         (lock (bt:make-lock "fetch"))
         (done (bt:make-condition-variable))
         (seen (make-hash-table :test 'equal)))
    (when (zerop n) (return-from fetch-events '()))
    (flet ((collect (event relay)
             (declare (ignore relay))
             (bt:with-lock-held (lock)
               (let ((id (cl-nostr.event:event-id event)))
                 (unless (gethash id seen)
                   (setf (gethash id seen) t)
                   (push event results)))))
           (eosed (relay)
             (declare (ignore relay))
             (bt:with-lock-held (lock)
               (incf eose)
               (when (>= eose n) (bt:condition-notify done)))))
      (let ((subs (loop for relay in relays
                        collect (cons relay (r:subscribe relay filters
                                                         :on-event #'collect
                                                         :on-eose #'eosed)))))
        (bt:with-lock-held (lock)
          (loop until (>= eose n)
                do (unless (bt:condition-wait done lock :timeout timeout)
                     (return))))
        (loop for (relay . sub) in subs do (ignore-errors (r:unsubscribe relay sub)))
        (let ((sorted (sort results #'> :key #'cl-nostr.event:event-created-at)))
          (if (and limit (> (length sorted) limit)) (subseq sorted 0 limit) sorted))))))

(defun fetch-one (pool filters &key (timeout 5))
  "Fetch the single newest event matching FILTERS, or NIL."
  (first (fetch-events pool filters :timeout timeout :limit 1)))

;;;; src/pool.lisp — a pool of relays: the high-level client surface.
;;;;
;;;; Nostr's redundancy model is "publish to many relays, read from many relays."
;;;; A pool fans publish/subscribe out to all its relays and (for fetch-events)
;;;; deduplicates the merged stream by event id, so the same note arriving from
;;;; three relays is delivered once.

(in-package #:cl-nostr.pool)

(defstruct (pool (:constructor %make-pool))
  (relays '() :type list)
  (subs '() :type list)          ; stored subscription specs, re-sent to a relay on reconnect
  (verify t)                     ; TLS verification, remembered for reconnects
  (watcher nil)                  ; keepalive + reconnect thread
  (lock (bt:make-lock "pool")))

(defparameter *pool-watch-interval* 20
  "Seconds between pool sweeps: ping live relays (relays drop idle sockets) and
reconnect + re-subscribe any that have gone away.")

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
  (let* ((pool (%make-pool :verify verify))
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
    (%ensure-watcher pool)                 ; keepalive + auto-reconnect from here on
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

;;; ---- keepalive + reconnect -------------------------------------------------
;;; websocket-driver never reconnects a dropped socket, and relays close idle ones,
;;; so a long-lived subscription silently dies.  The pool watcher pings live relays
;;; and, for any that have gone away, reconnects and re-sends the stored subscriptions.

(defun %resubscribe (pool relay)
  "Re-send every stored subscription to RELAY (after a reconnect)."
  (dolist (spec (pool-subs pool))
    (ignore-errors
     (r:subscribe relay (getf spec :filters)
                  :on-event (getf spec :dedup) :on-eose (getf spec :on-eose)))))

(defun %pool-sweep (pool)
  "One pass: ping connected relays; reconnect + re-subscribe disconnected ones.
Reconnects happen OUTSIDE the pool lock (the handshake blocks), swapping the fresh
relay into its cons cell in place so publish/subscribe keep seeing a live list."
  (let ((cells (bt:with-lock-held ((pool-lock pool))
                 (loop for cell on (pool-relays pool) collect cell))))
    (dolist (cell cells)
      (let ((relay (car cell)))
        (if (r:relay-connected-p relay)
            (r:relay-ping relay)                    ; keepalive (marks dead if the send fails)
            (let ((fresh (%connect-with-timeout (r:relay-url relay) (pool-verify pool) nil 10)))
              (when fresh
                (bt:with-lock-held ((pool-lock pool)) (setf (car cell) fresh))
                (%resubscribe pool fresh))))))))

(defun %pool-watch-loop (pool)
  (loop (sleep *pool-watch-interval*) (ignore-errors (%pool-sweep pool))))

(defun %ensure-watcher (pool)
  "Start the pool's keepalive/reconnect thread once."
  (bt:with-lock-held ((pool-lock pool))
    (unless (and (pool-watcher pool) (bt:thread-alive-p (pool-watcher pool)))
      (setf (pool-watcher pool)
            (bt:make-thread (lambda () (%pool-watch-loop pool)) :name "cl-nostr pool watcher")))))

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
  (let* ((seen (make-hash-table :test 'equal))
         (seen-lock (bt:make-lock "seen"))
         (dedup (lambda (event relay)
                  (when on-event
                    (let ((id (cl-nostr.event:event-id event)))
                      (when (bt:with-lock-held (seen-lock)
                              (unless (gethash id seen) (setf (gethash id seen) t)))
                        (funcall on-event event relay)))))))
    ;; remember this subscription so the watcher can re-send it after a reconnect
    (bt:with-lock-held ((pool-lock pool))
      (push (list :filters filters :dedup dedup :on-eose on-eose) (pool-subs pool)))
    (%ensure-watcher pool)
    (loop for relay in (%relays pool)
          collect (r:subscribe relay filters :on-event dedup :on-eose on-eose))))

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

;;;; src/blossom.lisp — Blossom blob upload/download (BUD-01/02) over Nostr auth.
;;;;
;;;; Blossom stores content-addressed blobs on ordinary HTTP servers, but gates
;;;; writes behind a *Nostr* signed authorization: a kind-24242 event, base64'd
;;;; and carried in the `Authorization: Nostr <b64>' header.  The blob's address
;;;; is the lowercase-hex SHA-256 of its bytes, so an upload is:
;;;;
;;;;   PUT <server>/upload   body = <octets>
;;;;   Authorization: Nostr base64(kind-24242 event with an ("x" <sha256>) tag)
;;;;
;;;; and the blob is thereafter fetchable at <server>/<sha256>.  See BUD-01
;;;; (auth events) and BUD-02 (upload/get) at github.com/hzrd149/blossom.
;;;;
;;;; TWO THINGS THIS LAYER INSISTS ON, both learned from a live deployment:
;;;;
;;;;   Every request is individually bounded.  Blossom servers are volunteer
;;;;   infrastructure; some do not refuse a request so much as never answer it.  An
;;;;   unbounded upload does not fail, it *hangs*, and it takes the whole publish
;;;;   with it — a blob went live and the manifest pointing at it was never written
;;;;   because the process sat on a PUT for twenty minutes.  See *BLOSSOM-TIMEOUT*.
;;;;
;;;;   A blob is verified against its address.  The address IS the SHA-256, so a
;;;;   download that does not hash to what was asked for is a failure, not a result.
;;;;   That check is what makes an untrusted mirror safe to read from.
;;;;
;;;; Fan-out (BLOSSOM-UPLOAD-ALL) reports rather than signals: publishing to three
;;;; servers of which one is down is the normal case, not an error, so the caller
;;;; gets one BLOB-UPLOAD record per server and decides what a good-enough result is.

(in-package #:cl-nostr.blossom)

(defconstant +unix-epoch+ 2208988800
  "Universal-time value of 1970-01-01T00:00:00Z.")

(defparameter *blossom-timeout* 45
  "Seconds any one Blossom request may take before it is abandoned.  NIL means no
deadline, which is almost always the wrong answer — see the header note.")

;;; ---- conditions ----------------------------------------------------------

(define-condition blossom-error (error)
  ((server :initarg :server :initform nil :reader blossom-error-server)
   (hash   :initarg :hash   :initform nil :reader blossom-error-hash)
   (status :initarg :status :initform nil :reader blossom-error-status)
   (detail :initarg :detail :initform nil :reader blossom-error-detail))
  (:report (lambda (c stream)
             (format stream "Blossom ~@[~a ~]failed~@[ (HTTP ~d)~]~@[: ~a~]"
                     (blossom-error-server c) (blossom-error-status c)
                     (blossom-error-detail c))))
  (:documentation "A single Blossom request failed: refused, unreachable, or out of time."))

;;; ---- outcome records -----------------------------------------------------
;;; Plain data describing what one server did.  CLOS rather than structures so a
;;; running image can be patched without stranding instances.

(defclass blob-upload ()
  ((server     :initarg :server     :reader upload-server
               :documentation "The Blossom base URL this record is about.")
   (hash       :initarg :hash       :reader upload-hash
               :documentation "Lowercase-hex SHA-256 of the bytes — known even if the upload failed.")
   (ok         :initarg :ok         :initform nil :reader upload-ok-p)
   (url        :initarg :url        :initform nil :reader upload-url
               :documentation "GET URL for the blob on this server, on success.")
   (descriptor :initarg :descriptor :initform nil :reader upload-descriptor
               :documentation "The blob descriptor the server returned, parsed, or NIL.")
   (error      :initarg :error      :initform nil :reader upload-error
               :documentation "Human-readable reason, when OK-P is false.")
   (seconds    :initarg :seconds    :initform 0   :reader upload-seconds))
  (:documentation "What one Blossom server did with one blob."))

(defmethod print-object ((u blob-upload) stream)
  (print-unreadable-object (u stream :type t)
    (format stream "~a ~a~@[ ~a~]" (upload-server u)
            (if (upload-ok-p u) "ok" "FAILED") (upload-error u))))

(defclass blob-fetch ()
  ((source   :initarg :source   :reader fetch-source
             :documentation "The URL that was read.")
   (expected :initarg :expected :initform nil :reader fetch-expected
             :documentation "The SHA-256 the body had to have, or NIL if anything goes.")
   (ok       :initarg :ok       :initform nil :reader fetch-ok-p
             :documentation "T iff the body arrived AND matched EXPECTED (when given).")
   (status   :initarg :status   :initform nil :reader fetch-status
             :documentation "HTTP status, or NIL if the request never completed.")
   (sha256   :initarg :sha256   :initform nil :reader fetch-sha256
             :documentation "Lowercase-hex SHA-256 of what actually arrived.")
   (bytes    :initarg :bytes    :initform nil :reader fetch-bytes)
   (error    :initarg :error    :initform nil :reader fetch-error)
   (seconds  :initarg :seconds  :initform 0   :reader fetch-seconds))
  (:documentation "What one HTTP GET returned, and whether it was the blob asked for."))

(defmethod print-object ((f blob-fetch) stream)
  (print-unreadable-object (f stream :type t)
    (format stream "~a ~@[http ~a ~]~a" (fetch-source f) (fetch-status f)
            (cond ((fetch-ok-p f) "ok")
                  ((fetch-error f) (fetch-error f))
                  ((fetch-expected f) "WRONG BODY")
                  (t "failed")))))

;;; ---- auth ----------------------------------------------------------------

(defun blossom-url (server hash)
  "The GET URL for a blob: \"<server>/<hash>\"."
  (format nil "~a/~a" (string-right-trim "/" server) hash))

(defun %auth-event (keypair hash &key (content "Upload") (ttl 3600))
  "A kind-24242 upload-authorization event for the blob SHA-256 HASH (hex)."
  (let ((expiration (+ (- (get-universal-time) +unix-epoch+) ttl)))
    (ev:build-event keypair 24242 content
                    :tags (list (list "t" "upload")
                                (list "x" hash)
                                (list "expiration" (princ-to-string expiration))))))

(defun %auth-header (keypair hash &rest args)
  "The value for the `Authorization' header: \"Nostr <base64(event-json)>\"."
  (let* ((event (apply #'%auth-event keypair hash args))
         (json (ev:event->json event))
         (b64 (b64:string-to-base64-string json)))
    (values (format nil "Nostr ~a" b64) event)))

;;; ---- upload --------------------------------------------------------------

(defun blossom-upload (server data keypair
                       &key (content-type "application/octet-stream")
                            (timeout *blossom-timeout*)
                            auth)
  "Upload DATA (octets) to the Blossom SERVER (a base URL, e.g.
\"https://blossom.band\"), authorized by KEYPAIR, giving up after TIMEOUT seconds.
Returns three values: the lowercase-hex SHA-256 of DATA (the blob address), the
parsed descriptor hash-table the server returned (or NIL), and the GET URL for the
blob.  Signals BLOSSOM-ERROR if this server did not take it — use
BLOSSOM-UPLOAD-ALL when a server being down is an expected outcome rather than an
error.

AUTH, if given, is a ready-made `Authorization' header value to use instead of
signing a fresh one; the kind-24242 authorization is about the BLOB, not about the
server, so one signature is valid at every server holding the same bytes."
  (let* ((bytes (coerce data '(vector (unsigned-byte 8))))
         (hash (u:bytes->hex (u:sha256 bytes)))
         (auth (or auth (%auth-header keypair hash)))
         (url (format nil "~a/upload" (string-right-trim "/" server))))
    (multiple-value-bind (body condition timed-out)
        (u:call-with-deadline timeout
                             (lambda ()
                               (dex:put url
                                        :content bytes
                                        :headers (list (cons "Authorization" auth)
                                                       (cons "Content-Type" content-type))
                                        :connect-timeout (and timeout (min 10 timeout))
                                        :read-timeout timeout))
                             :name (format nil "blossom upload ~a" server))
      (when timed-out
        (error 'blossom-error :server server :hash hash
                              :detail (format nil "no answer within ~a s" timeout)))
      (when condition
        (error 'blossom-error :server server :hash hash
                              :status (typecase condition
                                        (dexador.error:http-request-failed
                                         (dexador.error:response-status condition)))
                              :detail (princ-to-string condition)))
      (let ((descriptor (ignore-errors
                         (jzon:parse (if (stringp body) body (u:utf8->string body))))))
        (values hash descriptor (blossom-url server hash))))))

(defun blossom-upload-all (servers data keypair
                           &key (content-type "application/octet-stream")
                                (timeout *blossom-timeout*))
  "Upload DATA to every server in SERVERS at once, EACH INDIVIDUALLY BOUNDED by
TIMEOUT so one server that never answers cannot hold up the others or the caller.
Never signals: returns one BLOB-UPLOAD per server, in SERVERS order.  One success is
usually enough — the blob is content-addressed, so any server that has it will do.

The authorization is signed ONCE, here, before the fan-out.  That is not only an
economy: it keeps signing off the concurrent path entirely, and the same kind-24242
event authorizes this blob at every server."
  (let* ((servers (remove nil (if (listp servers) servers (list servers))))
         (hash (u:bytes->hex (u:sha256 (coerce data '(vector (unsigned-byte 8))))))
         (auth (%auth-header keypair hash))
         (runs (u:call-in-parallel
                (and timeout (+ timeout 10))
                (mapcar (lambda (server)
                          (lambda ()
                            (multiple-value-list
                             (blossom-upload server data keypair
                                             :content-type content-type
                                             :timeout timeout
                                             :auth auth))))
                        servers)
                :name "blossom upload")))
    (loop for server in servers
          for (result condition timed-out seconds) in runs
          collect (cond
                    (timed-out
                     (make-instance 'blob-upload :server server :hash hash :seconds seconds
                                                 :error (format nil "no answer within ~a s" timeout)))
                    (condition
                     (make-instance 'blob-upload :server server :hash hash :seconds seconds
                                                 :error (princ-to-string condition)))
                    (t
                     (destructuring-bind (&optional got descriptor url) result
                       (make-instance 'blob-upload :server server :hash (or got hash)
                                                   :ok t :url url :descriptor descriptor
                                                   :seconds seconds)))))))

;;; ---- download ------------------------------------------------------------

(defun blossom-fetch (url &key expect (timeout *blossom-timeout*))
  "GET URL as octets, bounded by TIMEOUT, and hash what comes back.  EXPECT, if
given, is the lowercase-hex SHA-256 the body must have; the fetch is only OK-P when
it matches.  Never signals — returns a BLOB-FETCH describing what happened.  Works
for any URL that serves the bytes, Blossom server or nsite gateway alike."
  (multiple-value-bind (result condition timed-out seconds)
      (u:call-with-deadline timeout
                           (lambda ()
                             (multiple-value-bind (body status)
                                 (dex:get url :force-binary t
                                              :connect-timeout (and timeout (min 10 timeout))
                                              :read-timeout timeout)
                               (list body status)))
                           :name (format nil "blossom fetch ~a" url))
    (cond
      (timed-out
       (make-instance 'blob-fetch :source url :expected expect :seconds seconds
                                  :error (format nil "no answer within ~a s" timeout)))
      (condition
       (make-instance 'blob-fetch :source url :expected expect :seconds seconds
                                  :status (typecase condition
                                            (dexador.error:http-request-failed
                                             (dexador.error:response-status condition)))
                                  :error (princ-to-string condition)))
      (t
       (destructuring-bind (body status) result
         (let* ((bytes (coerce body '(vector (unsigned-byte 8))))
                (got (u:bytes->hex (u:sha256 bytes))))
           (make-instance 'blob-fetch
                          :source url :expected expect :status status
                          :sha256 got :bytes bytes :seconds seconds
                          :ok (and (eql status 200)
                                   (or (null expect) (string-equal got expect)))
                          :error (when (and expect (not (string-equal got expect)))
                                   "wrong body for this hash"))))))))

(defun blossom-download (server hash &key (timeout *blossom-timeout*))
  "Fetch blob HASH from one Blossom SERVER, verifying the body against HASH.
Returns a BLOB-FETCH; never signals."
  (blossom-fetch (blossom-url server hash) :expect hash :timeout timeout))

(defun blossom-download-any (servers hash &key (timeout *blossom-timeout*))
  "Try each server in SERVERS in turn until one returns a body that really hashes to
HASH.  Returns two values: the octets (or NIL) and the list of BLOB-FETCH records
tried, so a caller can report which mirrors were wrong rather than merely absent."
  (let ((tried '()))
    (dolist (server (remove nil (if (listp servers) servers (list servers)))
                    (values nil (nreverse tried)))
      (let ((fetch (blossom-download server hash :timeout timeout)))
        (push fetch tried)
        (when (fetch-ok-p fetch)
          (return (values (fetch-bytes fetch) (nreverse tried))))))))

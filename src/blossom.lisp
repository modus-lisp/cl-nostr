;;;; src/blossom.lisp — Blossom blob upload (BUD-01/02) over Nostr auth.
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

(in-package #:cl-nostr.blossom)

(defconstant +unix-epoch+ 2208988800
  "Universal-time value of 1970-01-01T00:00:00Z.")

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

(defun blossom-upload (server data keypair
                       &key (content-type "application/octet-stream"))
  "Upload DATA (octets) to the Blossom SERVER (a base URL, e.g.
\"https://blossom.band\"), authorized by KEYPAIR.  Returns three values: the
lowercase-hex SHA-256 of DATA (the blob address), the parsed descriptor
hash-table the server returned (or NIL), and the GET URL for the blob."
  (let* ((bytes (coerce data '(vector (unsigned-byte 8))))
         (hash (u:bytes->hex (u:sha256 bytes)))
         (auth (%auth-header keypair hash))
         (url (format nil "~a/upload" (string-right-trim "/" server))))
    (multiple-value-bind (body status headers)
        (handler-case
            (dex:put url
                     :content bytes
                     :headers (list (cons "Authorization" auth)
                                    (cons "Content-Type" content-type)))
          (dexador.error:http-request-failed (e)
            (error "Blossom upload to ~a failed: HTTP ~d~@[ ~a~]"
                   url
                   (dexador.error:response-status e)
                   (dexador.error:response-body e))))
      (declare (ignore status headers))
      (let ((descriptor (ignore-errors
                         (jzon:parse (if (stringp body) body (u:utf8->string body))))))
        (values hash descriptor (blossom-url server hash))))))

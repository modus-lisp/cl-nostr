;;;; src/event.lisp — NIP-01 events.
;;;;
;;;; An event is { id, pubkey, created_at, kind, tags, content, sig }.  The id is
;;;; the SHA-256 of a *canonical* UTF-8 serialization:
;;;;
;;;;   [0, <pubkey-hex>, <created_at>, <kind>, <tags>, <content>]
;;;;
;;;; with no insignificant whitespace and a fixed string-escape set.  Getting
;;;; that byte-exact is the whole game: relays recompute the id and reject any
;;;; mismatch, so we serialize with our own escaper (below) rather than trust a
;;;; general JSON printer's choices.  The signature is BIP340 Schnorr over the id.

(in-package #:cl-nostr.event)

(defconstant +unix-epoch+ 2208988800
  "Universal-time value of 1970-01-01T00:00:00Z.")

(defun now () (- (get-universal-time) +unix-epoch+))

;;; Common event kinds (NIP-01 / NIP-02 / NIP-04 / NIP-09 / NIP-25).
(defconstant +kind-metadata+ 0)
(defconstant +kind-text-note+ 1)
(defconstant +kind-contacts+ 3)
(defconstant +kind-dm+ 4)
(defconstant +kind-deletion+ 5)
(defconstant +kind-reaction+ 7)

(defstruct (event (:constructor %make-event))
  "A Nostr event.  ID/PUBKEY/SIG are lowercase hex strings; TAGS is a list of
lists of strings; CONTENT is a string; CREATED-AT and KIND are integers."
  (id nil)
  (pubkey nil)
  (created-at 0 :type integer)
  (kind 1 :type integer)
  (tags '() :type list)
  (content "" :type string)
  (sig nil))

(defun make-event (&rest args) (apply #'%make-event args))

;;; ---- canonical JSON ------------------------------------------------------

(defun %escape-string (string out)
  "Write STRING to stream OUT with NIP-01 escaping, wrapped in double quotes."
  (write-char #\" out)
  (loop for ch across string
        for code = (char-code ch)
        do (case code
             (#x08 (write-string "\\b" out))
             (#x09 (write-string "\\t" out))
             (#x0A (write-string "\\n" out))
             (#x0C (write-string "\\f" out))
             (#x0D (write-string "\\r" out))
             (#x22 (write-string "\\\"" out))
             (#x5C (write-string "\\\\" out))
             (t (write-char ch out))))
  (write-char #\" out))

(defun %write-tags (tags out)
  (write-char #\[ out)
  (loop for tag in tags for first = t then nil do
    (unless first (write-char #\, out))
    (write-char #\[ out)
    (loop for item in tag for f = t then nil do
      (unless f (write-char #\, out))
      (%escape-string (string item) out))
    (write-char #\] out))
  (write-char #\] out))

(defun serialize-for-id (pubkey created-at kind tags content)
  "The canonical UTF-8 byte vector that the event id is the SHA-256 of."
  (let ((s (with-output-to-string (out)
             (write-string "[0," out)
             (%escape-string pubkey out)
             (format out ",~d,~d," created-at kind)
             (%write-tags tags out)
             (write-char #\, out)
             (%escape-string content out)
             (write-char #\] out))))
    (u:string->utf8 s)))

(defun compute-id (pubkey created-at kind tags content)
  "Lowercase-hex SHA-256 event id."
  (u:bytes->hex (u:sha256 (serialize-for-id pubkey created-at kind tags content))))

;;; ---- build / sign / verify ----------------------------------------------

(defun build-event (keypair kind content &key tags (created-at (now)))
  "Build, id, and sign an event authored by KEYPAIR.  Returns a complete EVENT."
  (let* ((pubkey (cl-nostr.keys:public-hex keypair))
         (id (compute-id pubkey created-at kind tags content))
         (sig (u:bytes->hex (cl-nostr.keys:sign keypair id))))
    (%make-event :id id :pubkey pubkey :created-at created-at
                 :kind kind :tags tags :content content :sig sig)))

(defun sign-event (event keypair)
  "Fill in EVENT's pubkey/id/sig from KEYPAIR (mutates and returns EVENT)."
  (setf (event-pubkey event) (cl-nostr.keys:public-hex keypair)
        (event-id event) (compute-id (event-pubkey event) (event-created-at event)
                                     (event-kind event) (event-tags event)
                                     (event-content event))
        (event-sig event) (u:bytes->hex (cl-nostr.keys:sign keypair (event-id event))))
  event)

(defun verify-event (event)
  "T iff EVENT's id matches its contents and its signature verifies."
  (and (event-id event) (event-sig event) (event-pubkey event)
       (string= (event-id event)
                (compute-id (event-pubkey event) (event-created-at event)
                            (event-kind event) (event-tags event)
                            (event-content event)))
       (cl-nostr.keys:verify (event-pubkey event) (event-id event) (event-sig event))))

(defun valid-event-p (event) (ignore-errors (verify-event event)))

;;; ---- JSON in/out ---------------------------------------------------------

(defun event->json (event)
  "Serialize a complete EVENT to a JSON object string (id/sig included)."
  (with-output-to-string (out)
    (write-string "{\"id\":" out) (%escape-string (event-id event) out)
    (write-string ",\"pubkey\":" out) (%escape-string (event-pubkey event) out)
    (format out ",\"created_at\":~d,\"kind\":~d,\"tags\":"
            (event-created-at event) (event-kind event))
    (%write-tags (event-tags event) out)
    (write-string ",\"content\":" out) (%escape-string (event-content event) out)
    (write-string ",\"sig\":" out) (%escape-string (event-sig event) out)
    (write-char #\} out)))

(defun %as-string (x) (if (stringp x) x (princ-to-string x)))

(defun %parse-tags (jtags)
  "jzon parses arrays to simple-vectors; normalize tags to a list of lists of strings."
  (when jtags
    (map 'list (lambda (tag) (map 'list #'%as-string tag)) jtags)))

(defun json->event (json)
  "Parse a JSON object STRING (or an already-parsed hash-table) into an EVENT."
  (let ((ht (if (stringp json) (com.inuoe.jzon:parse json) json)))
    (flet ((g (k) (gethash k ht)))
      (%make-event
       :id (g "id")
       :pubkey (g "pubkey")
       :created-at (truncate (or (g "created_at") 0))
       :kind (truncate (or (g "kind") 1))
       :tags (%parse-tags (g "tags"))
       :content (or (g "content") "")
       :sig (g "sig")))))

(defun event->plist (event)
  (list :id (event-id event) :pubkey (event-pubkey event)
        :created-at (event-created-at event) :kind (event-kind event)
        :tags (event-tags event) :content (event-content event) :sig (event-sig event)))

;;; ---- tag helpers ---------------------------------------------------------

(defun tag-values (event name)
  "All values (the 2nd element) of tags whose name is NAME, e.g. \"e\" or \"p\"."
  (loop for tag in (event-tags event)
        when (and (cdr tag) (string= (car tag) name))
          collect (second tag)))

(defun first-tag-value (event name)
  (first (tag-values event name)))

(defun e-tags (event) (tag-values event "e"))   ; referenced event ids
(defun p-tags (event) (tag-values event "p"))   ; referenced pubkeys

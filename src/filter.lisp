;;;; src/filter.lisp — NIP-01 subscription filters.
;;;;
;;;; A filter selects events: ids/authors/kinds are sets (match if the event's
;;;; field is in the set); #e/#p (and other #<single-letter>) match tag values;
;;;; since/until bound created_at; limit caps the initial reply.  An event matches
;;;; a filter iff *every* present condition holds (AND); a relay matches an event
;;;; against a list of filters with OR.

(in-package #:cl-nostr.filter)

(defstruct (filter (:constructor %make-filter))
  (ids nil :type list)          ; event id hex prefixes/values
  (authors nil :type list)      ; pubkey hex
  (kinds nil :type list)        ; integers
  (tags nil :type list)         ; alist: ("e" . (vals...)) for #e, etc.
  (since nil)                   ; unix ts (inclusive)
  (until nil)                   ; unix ts (inclusive)
  (limit nil)                   ; integer
  (search nil))                 ; NIP-50 full-text query

(defun make-filter (&key ids authors kinds tags since until limit search)
  "Build a filter.  TAGS is an alist of (single-letter-string . list-of-values),
e.g. '((\"e\" . (\"<id>\")) (\"p\" . (\"<pubkey>\")))."
  (%make-filter :ids ids :authors authors :kinds kinds :tags tags
                :since since :until until :limit limit :search search))

(defun %write-string-array (values out)
  (write-char #\[ out)
  (loop for v in values for first = t then nil do
    (unless first (write-char #\, out))
    (format out "~s" (string v)))         ; hex/ascii: ~s gives a quoted JSON-safe token
  (write-char #\] out))

(defun %write-int-array (values out)
  (write-char #\[ out)
  (loop for v in values for first = t then nil do
    (unless first (write-char #\, out))
    (format out "~d" v))
  (write-char #\] out))

(defun filter->json (filter)
  "Serialize FILTER to a JSON object string (omitting empty fields)."
  (with-output-to-string (out)
    (write-char #\{ out)
    (let ((first t))
      (flet ((comma () (if first (setf first nil) (write-char #\, out))))
        (when (filter-ids filter)
          (comma) (write-string "\"ids\":" out) (%write-string-array (filter-ids filter) out))
        (when (filter-authors filter)
          (comma) (write-string "\"authors\":" out) (%write-string-array (filter-authors filter) out))
        (when (filter-kinds filter)
          (comma) (write-string "\"kinds\":" out) (%write-int-array (filter-kinds filter) out))
        (dolist (tag (filter-tags filter))
          (comma) (format out "\"#~a\":" (car tag)) (%write-string-array (cdr tag) out))
        (when (filter-since filter)
          (comma) (format out "\"since\":~d" (filter-since filter)))
        (when (filter-until filter)
          (comma) (format out "\"until\":~d" (filter-until filter)))
        (when (filter-limit filter)
          (comma) (format out "\"limit\":~d" (filter-limit filter)))
        (when (filter-search filter)
          (comma) (format out "\"search\":~s" (filter-search filter)))))
    (write-char #\} out)))

(defun %prefix-or-eq (set value)
  "NIP-01 ids/authors match by exact value OR by hex prefix."
  (some (lambda (s) (or (string= s value)
                        (and (<= (length s) (length value))
                             (string= s (subseq value 0 (length s))))))
        set))

(defun filter-matches-p (filter event)
  "T iff EVENT satisfies every present condition of FILTER."
  (let ((id (cl-nostr.event:event-id event))
        (pk (cl-nostr.event:event-pubkey event))
        (kind (cl-nostr.event:event-kind event))
        (ts (cl-nostr.event:event-created-at event)))
    (and (or (null (filter-ids filter)) (%prefix-or-eq (filter-ids filter) id))
         (or (null (filter-authors filter)) (%prefix-or-eq (filter-authors filter) pk))
         (or (null (filter-kinds filter)) (member kind (filter-kinds filter)))
         (or (null (filter-since filter)) (>= ts (filter-since filter)))
         (or (null (filter-until filter)) (<= ts (filter-until filter)))
         (every (lambda (tag)
                  (let ((want (cdr tag))
                        (have (cl-nostr.event:tag-values event (car tag))))
                    (some (lambda (v) (member v want :test #'string=)) have)))
                (filter-tags filter)))))

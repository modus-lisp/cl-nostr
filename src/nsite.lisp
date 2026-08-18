;;;; src/nsite.lisp — nsite: a static website addressed by a Nostr pubkey (NIP-5A).
;;;;
;;;; The current format (NIP-5A) is a single ROOT-SITE MANIFEST event, kind 15128,
;;;; whose `path' tags map absolute paths to Blossom blob hashes:
;;;;
;;;;   kind 15128, tags ("path" "/index.html" <sha256>) ... ("server" <blossom url>) ...
;;;;
;;;; A gateway resolves <npub>.<gateway>/PATH by reading the author's kind-15128
;;;; event, finding the matching `path' tag, reading its hash, and GETting that blob
;;;; from a Blossom server (the `server' tags hint where; the author's kind-10063 list
;;;; is also consulted).  kind 34128 — one replaceable event per path — is the LEGACY
;;;; format, still accepted by some gateways for back-compat via NSITE-PUT.
;;;;
;;;; This file covers both halves of using that format:
;;;;
;;;;   PUBLISH  NSITE-PUBLISH — blobs to many Blossom servers, then the manifest and
;;;;            the two discovery lists (kind 10002 relays, kind 10063 servers) to
;;;;            many relays, returning a report of what every one of them did.
;;;;
;;;;   RESOLVE  NSITE-RESOLVE — the client half: given an npub and a path, find the
;;;;            manifest, the hash, and the bytes, verified against that hash.
;;;;
;;;; A PARTIAL RESULT IS THE NORMAL RESULT.  Some Blossom servers will be down and
;;;; some relays will refuse the event; neither is an error and neither should abort a
;;;; publish.  So nothing here signals on a peer's behaviour — it reports.  The one
;;;; thing that IS refused is publishing a manifest naming a blob that no server
;;;; accepted, because that is a site that points at nothing (see :REQUIRE-BLOBS).

(in-package #:cl-nostr.nsite)

(defconstant +kind-nsite-root+ 15128
  "NIP-5A root-site manifest (path->blob), a replaceable event, one per pubkey.")
(defconstant +kind-nsite-legacy+ 34128
  "Legacy per-path nsite pointer (deprecated; prefer the kind-15128 manifest).")
(defconstant +kind-relay-list+ 10002
  "NIP-65 relay list: where this author publishes and can be read.")
(defconstant +kind-server-list+ 10063
  "BUD-03 Blossom server list: where this author's blobs live.")

(defparameter *discovery-relays*
  '("wss://relay.damus.io" "wss://nos.lol" "wss://relay.primal.net" "wss://purplepag.es")
  "Relays used when a caller supplies none.  Resolving an nsite from nothing but an
npub has to start somewhere; these are widely-readable public relays that carry the
replaceable events (10002/10063/15128) an nsite is discovered through.")

;;; ---- addressing ----------------------------------------------------------

(defun %pubkey (who) (b:pubkey-hex who))
(defun %npub (who) (b:npub-encode (b:pubkey-hex who)))

(defmacro %with-pool ((var where) &body body)
  "Bind VAR to a pool for WHERE — which may be a POOL (used as-is), a list of relay
urls, a single url, or NIL for *DISCOVERY-RELAYS*.  A pool we opened is closed again;
a pool we were handed is left alone."
  (let ((ours (gensym "OURS")) (w (gensym "WHERE")))
    `(let* ((,w ,where)
            (,ours (unless (pool:pool-p ,w)
                     (pool:make-pool (cond ((null ,w) *discovery-relays*)
                                           ((listp ,w) ,w)
                                           (t (list ,w))))))
            (,var (or ,ours ,w)))
       (unwind-protect (progn ,@body)
         (when ,ours (pool:close-pool ,ours))))))

;;; ---- the manifest, as data -----------------------------------------------

(defun nsite-manifest (keypair paths &key servers title description)
  "Build and return a NIP-5A kind-15128 root-site manifest event.  PATHS is a list of
(path . sha256-hex) conses; SERVERS an optional list of Blossom server URLs hinting where the
blobs live; TITLE/DESCRIPTION optional site metadata.  Signed by KEYPAIR — hand it to
POOL-PUBLISH-SYNC."
  (ev:build-event keypair +kind-nsite-root+ ""
    :tags (append (mapcar (lambda (p) (list "path" (car p) (cdr p))) paths)
                  (mapcar (lambda (s) (list "server" s)) servers)
                  (when title       (list (list "title" title)))
                  (when description (list (list "description" description))))))

(defun manifest-paths (manifest)
  "The (path . sha256-hex) alist a kind-15128 MANIFEST maps, in tag order."
  (loop for tag in (ev:event-tags manifest)
        when (and (>= (length tag) 3) (string= (first tag) "path"))
          collect (cons (second tag) (third tag))))

(defun manifest-servers (manifest)
  "The Blossom server hints (`server' tags) in a kind-15128 MANIFEST."
  (ev:tag-values manifest "server"))

(defun manifest-title (manifest) (ev:first-tag-value manifest "title"))
(defun manifest-description (manifest) (ev:first-tag-value manifest "description"))

(defun %path-candidates (path)
  "The paths a gateway would try for a request for PATH, in order.  A site is served
over HTTP, so \"/\" and \"/docs/\" mean the directory's index — a manifest that maps
only \"/index.html\" still answers a request for \"/\"."
  (let* ((path (if (and (plusp (length path)) (char= (char path 0) #\/))
                   path
                   (concatenate 'string "/" path)))
         (path (if (string= path "") "/" path)))
    (remove-duplicates
     (cons path
           (cond ((char= (char path (1- (length path))) #\/)
                  (list (concatenate 'string path "index.html")))
                 ;; a last segment with no extension reads as a directory
                 ((not (find #\. path :start (1+ (or (position #\/ path :from-end t) 0))))
                  (list (concatenate 'string path "/index.html")))))
     :test #'string= :from-end t)))

(defun manifest-lookup (manifest path)
  "Look PATH up in MANIFEST the way a gateway would.  Returns two values: the blob
hash and the manifest path that actually matched (which may be PATH plus
\"index.html\"), or NIL if the site does not have it."
  (let ((paths (manifest-paths manifest)))
    (dolist (candidate (%path-candidates path) (values nil nil))
      (let ((hit (assoc candidate paths :test #'string=)))
        (when hit (return (values (cdr hit) (car hit))))))))

;;; ---- discovery lists ------------------------------------------------------
;;; Neither list is nsite's invention — 10002 is NIP-65 and 10063 is BUD-03 — but an
;;; nsite is only findable if both are published, so the builders live here.

(defun relay-list-event (keypair relays)
  "A NIP-65 kind-10002 relay list: where this author publishes and can be read."
  (ev:build-event keypair +kind-relay-list+ ""
                  :tags (mapcar (lambda (r) (list "r" r)) relays)))

(defun server-list-event (keypair servers)
  "A BUD-03 kind-10063 Blossom server list: where this author's blobs can be fetched."
  (ev:build-event keypair +kind-server-list+ ""
                  :tags (mapcar (lambda (s) (list "server" s)) servers)))

;;; ---- publish: what every server and every relay did -----------------------

(defclass publication ()
  ((event :initarg :event :reader publication-event)
   (acks  :initarg :acks  :initform '() :reader publication-acks))
  (:documentation "One event and what each relay said about it."))

(defun publication-kind (publication) (ev:event-kind (publication-event publication)))
(defun publication-accepted (publication)
  "The acks whose relay accepted this event.  Empty means it was NOT published."
  (pool:acks-accepted (publication-acks publication)))

(defmethod print-object ((p publication) stream)
  (print-unreadable-object (p stream :type t)
    (format stream "kind ~d ~d/~d accepted" (publication-kind p)
            (length (publication-accepted p)) (length (publication-acks p)))))

(defclass nsite-report ()
  ((npub         :initarg :npub         :reader report-npub)
   (pubkey       :initarg :pubkey       :reader report-pubkey)
   (paths        :initarg :paths        :initform '() :reader report-paths
                 :documentation "The (path . sha256-hex) alist the manifest was built from.")
   (uploads      :initarg :uploads      :initform '() :reader report-uploads
                 :documentation "Every BLOB-UPLOAD attempted, blob by blob, server by server.")
   (publications :initarg :publications :initform '() :reader report-publications
                 :documentation "Each event published, with its per-relay acks."))
  (:documentation "What a publish actually accomplished.  Deliberately not a boolean:
a publish where one Blossom server timed out and one relay refused the event is a
successful publish, and the caller is the only one who can say so."))

(defmethod print-object ((r nsite-report) stream)
  (print-unreadable-object (r stream :type t)
    (format stream "~a ~d path~:p~@[ — ~{~a~^; ~}~]"
            (report-npub r) (length (report-paths r)) (report-problems r))))

(defun report-publication (report kind)
  "The PUBLICATION for the event of KIND (e.g. +KIND-NSITE-ROOT+), or NIL."
  (find kind (report-publications report) :key #'publication-kind))

(defun report-manifest (report)
  "The manifest publication — the one that decides whether the site changed."
  (report-publication report +kind-nsite-root+))

(defun report-blob-uploads (report hash)
  "The upload attempts for one blob HASH, one per server."
  (remove-if-not (lambda (upload) (string= hash (blossom:upload-hash upload)))
                 (report-uploads report)))

(defun report-stored-p (report &optional hash)
  "T iff every distinct blob (or just HASH) reached at least one Blossom server."
  (let ((hashes (if hash (list hash)
                    (remove-duplicates (mapcar #'cdr (report-paths report)) :test #'string=))))
    (every (lambda (h) (some #'blossom:upload-ok-p (report-blob-uploads report h))) hashes)))

(defun report-published-p (report)
  "T iff at least one relay accepted the manifest — the site is now live for readers
of that relay.  Zero accepted acks means nothing was published, whatever else printed."
  (let ((manifest (report-manifest report)))
    (and manifest (plusp (length (publication-accepted manifest))))))

(defun report-problems (report)
  "A list of human-readable strings naming what did not work, empty if all is well.
Only real breakage: a server or relay declining is expected and is not listed."
  (append
   (loop for hash in (remove-duplicates (mapcar #'cdr (report-paths report)) :test #'string=)
         unless (report-stored-p report hash)
           collect (format nil "no Blossom server stored ~a" (subseq hash 0 (min 16 (length hash)))))
   (unless (report-manifest report)
     (list "the manifest was never published"))
   (when (and (report-manifest report) (not (report-published-p report)))
     (list "no relay accepted the manifest"))))

(defun report-ok-p (report) (null (report-problems report)))

;;; ---- publish ---------------------------------------------------------------

(defparameter *content-types*
  '(("html" . "text/html") ("htm" . "text/html") ("css" . "text/css")
    ("js" . "text/javascript") ("mjs" . "text/javascript") ("json" . "application/json")
    ("svg" . "image/svg+xml") ("png" . "image/png") ("jpg" . "image/jpeg")
    ("jpeg" . "image/jpeg") ("gif" . "image/gif") ("webp" . "image/webp")
    ("ico" . "image/x-icon") ("txt" . "text/plain") ("xml" . "application/xml")
    ("wasm" . "application/wasm") ("woff" . "font/woff") ("woff2" . "font/woff2"))
  "Extension -> Content-Type, for guessing what to tell Blossom about a file.")

(defun %content-type-for (path)
  (let* ((dot (position #\. path :from-end t))
         (ext (and dot (string-downcase (subseq path (1+ dot))))))
    (or (cdr (assoc ext *content-types* :test #'equal)) "application/octet-stream")))

(defun %octets (content)
  (etypecase content
    (string (u:string->utf8 content))
    (sequence (coerce content '(vector (unsigned-byte 8))))))

(defun %blobs (files content-type)
  "Group FILES ((path . content) conses) by content hash.  Returns two values: the
(path . hash) alist in FILES order, and a list of (hash bytes content-type paths) —
one entry per DISTINCT blob, because Blossom is content-addressed and a site whose
\"/\" and \"/index.html\" are the same bytes should be uploaded once, not twice."
  (let ((paths '()) (blobs '()))
    (dolist (file files)
      (let* ((path (car file))
             (bytes (%octets (cdr file)))
             (hash (u:bytes->hex (u:sha256 bytes)))
             (blob (assoc hash blobs :test #'string=)))
        (push (cons path hash) paths)
        (if blob
            (push path (fourth blob))
            ;; the first path to name a blob decides its content type
            (push (list hash bytes
                        (etypecase content-type
                          (null (%content-type-for path))
                          (string content-type)
                          (function (funcall content-type path)))
                        (list path))
                  blobs))))
    (values (nreverse paths) (nreverse blobs))))

(defun nsite-publish (where servers keypair files
                      &key relays title description content-type
                           (timeout blossom:*blossom-timeout*)
                           (publish-timeout 8) (require-blobs t) (lists t)
                           on-upload on-publish)
  "Publish a whole static site (NIP-5A, kind 15128) and report what happened.

WHERE is a POOL, a list of relay urls, or NIL for *DISCOVERY-RELAYS*.  SERVERS is one
Blossom base url or a list of them; FILES a list of (PATH . CONTENT) conses where
CONTENT is octets or a string.  Distinct blobs are uploaded ONCE EACH to EVERY server,
in parallel, each upload individually bounded by TIMEOUT — one server that never
answers cannot strand the publish.  Then the kind-15128 manifest is published and
waited on, and (unless :LISTS is NIL) the kind-10002 relay list and kind-10063 server
list, so a gateway can discover both.  RELAYS defaults to the pool's connected relays;
:SERVERS values are written into the manifest as `server' hints.

CONTENT-TYPE may be a string for every file, a function of the path, or NIL to guess
from the extension.  ON-UPLOAD and ON-PUBLISH, if given, are called with each
BLOB-UPLOAD and each PUBLICATION as it completes, for callers that want to report
progress rather than wait for the end.

Returns two values: the site's npub and an NSITE-REPORT.  With :REQUIRE-BLOBS true
(the default) the manifest is NOT published if any blob reached no server at all —
publishing a manifest that names a blob nobody has is how a live site goes dark."
  (let* ((servers (remove nil (if (listp servers) servers (list servers))))
         (pubkey (k:public-hex keypair))
         (npub (b:npub-encode pubkey)))
    (%with-pool (pool where)
      (multiple-value-bind (paths blobs) (%blobs files content-type)
        (let ((uploads '()))
          (dolist (blob blobs)
            (destructuring-bind (hash bytes type blob-paths) blob
              (declare (ignore hash blob-paths))
              (dolist (upload (blossom:blossom-upload-all servers bytes keypair
                                                          :content-type type
                                                          :timeout timeout))
                (push upload uploads)
                (when on-upload (funcall on-upload upload)))))
          (setf uploads (nreverse uploads))
          (let ((report (make-instance 'nsite-report :npub npub :pubkey pubkey
                                                     :paths paths :uploads uploads)))
            (if (and require-blobs (not (report-stored-p report)))
                (values npub report)      ; nothing pointed anywhere: do not move the site
                (let ((events (append
                               (list (nsite-manifest keypair paths
                                                     :servers servers
                                                     :title title
                                                     :description description))
                               (when lists
                                 (let ((relays (or relays (pool:pool-relay-urls pool))))
                                   (append (when relays (list (relay-list-event keypair relays)))
                                           (when servers (list (server-list-event keypair servers)))))))))
                  (setf (slot-value report 'publications)
                        (mapcar (lambda (event)
                                  (let ((publication
                                          (make-instance 'publication :event event
                                                         :acks (pool:pool-publish-sync
                                                                pool event :timeout publish-timeout))))
                                    (when on-publish (funcall on-publish publication))
                                    publication))
                                events))
                  (values npub report)))))))))

(defun nsite-put (pool keypair path hash)
  "LEGACY (kind 34128): publish one replaceable path->blob pointer, tags (\"d\" PATH)
(\"x\" HASH).  Prefer NSITE-PUBLISH / NSITE-MANIFEST (kind 15128) for new sites.
Returns two values: the event and its per-relay RELAY-ACKs."
  (let ((event (ev:build-event keypair +kind-nsite-legacy+ ""
                               :tags (list (list "d" path) (list "x" hash)))))
    (values event (pool:pool-publish-sync pool event))))

;;; ---- resolve: what a reader actually gets ---------------------------------
;;; The client half.  Everything below needs only an npub — no secret, nothing local.

(defun nsite-fetch-manifests (where who &key (timeout 5) (limit 4))
  "Every kind-15128 manifest the relays hold for WHO, newest first.  Plural on
purpose: 15128 is replaceable, so relays SHOULD agree, and when they do not — one
relay still serving last week's manifest — that disagreement is the diagnosis."
  (%with-pool (pool where)
    (pool:fetch-events pool
                       (list (flt:make-filter :kinds (list +kind-nsite-root+)
                                              :authors (list (%pubkey who))
                                              :limit limit))
                       :timeout timeout)))

(defun nsite-fetch-manifest (where who &key (timeout 5))
  "The newest kind-15128 manifest for WHO, or NIL if the relays have none."
  (first (nsite-fetch-manifests where who :timeout timeout :limit 4)))

(defun legacy-pointer (event)
  "The (path . hash) a legacy kind-34128 EVENT points at — its (\"d\" PATH) and
(\"x\" HASH) tags — or NIL if it is not one.  The inverse of NSITE-PUT's tags."
  (let ((d (ev:first-tag-value event "d"))
        (x (ev:first-tag-value event "x")))
    (when (and (eql (ev:event-kind event) +kind-nsite-legacy+) d x)
      (cons d x))))

(defun nsite-fetch-legacy (where who &key path (timeout 5) (limit 50))
  "The legacy kind-34128 per-path pointers for WHO as a (path . hash) alist.  PATH, if
given, asks only for that one."
  (%with-pool (pool where)
    (let ((events (pool:fetch-events
                   pool
                   (list (flt:make-filter :kinds (list +kind-nsite-legacy+)
                                          :authors (list (%pubkey who))
                                          :tags (when path (list (cons "d" (list path))))
                                          :limit limit))
                   :timeout timeout)))
      ;; newest first from FETCH-EVENTS, so the first entry per path wins
      (let ((seen '()))
        (loop for event in events
              for pointer = (legacy-pointer event)
              when (and pointer (not (member (car pointer) seen :test #'string=)))
                do (push (car pointer) seen)
                and collect pointer)))))

(defun nsite-relays (where who &key (timeout 5))
  "WHO's advertised relay list (kind 10002) — where a gateway should look for them."
  (%with-pool (pool where)
    (let ((event (pool:fetch-one pool
                                 (list (flt:make-filter :kinds (list +kind-relay-list+)
                                                        :authors (list (%pubkey who))))
                                 :timeout timeout)))
      (and event (ev:tag-values event "r")))))

(defun nsite-servers (where who &key manifest (timeout 5))
  "Where WHO's blobs can be fetched: the MANIFEST's `server' hints first (they are the
most specific statement about these blobs), then the kind-10063 list, deduplicated."
  (%with-pool (pool where)
    (let* ((manifest (or manifest (nsite-fetch-manifest pool who :timeout timeout)))
           (event (pool:fetch-one pool
                                  (list (flt:make-filter :kinds (list +kind-server-list+)
                                                         :authors (list (%pubkey who))))
                                  :timeout timeout)))
      (remove-duplicates (append (and manifest (manifest-servers manifest))
                                 (and event (ev:tag-values event "server")))
                         :test #'string= :from-end t))))

(defclass nsite-resolution ()
  ((npub         :initarg :npub         :reader resolution-npub)
   (pubkey       :initarg :pubkey       :reader resolution-pubkey)
   (path         :initarg :path         :reader resolution-path
                 :documentation "The path that was asked for.")
   (matched-path :initarg :matched-path :initform nil :reader resolution-matched-path
                 :documentation "The path the site actually maps, e.g. \"/index.html\" for \"/\".")
   (hash         :initarg :hash         :initform nil :reader resolution-hash)
   (source       :initarg :source       :initform nil :reader resolution-source
                 :documentation ":MANIFEST (kind 15128) or :LEGACY (kind 34128).")
   (manifest     :initarg :manifest     :initform nil :reader resolution-manifest)
   (servers      :initarg :servers      :initform '() :reader resolution-servers
                 :documentation "The Blossom servers that were going to be tried.")
   (fetches      :initarg :fetches      :initform '() :reader resolution-fetches
                 :documentation "One BLOB-FETCH per server tried, in order.")
   (server       :initarg :server       :initform nil :reader resolution-server
                 :documentation "The URL that actually served the verified bytes.")
   (bytes        :initarg :bytes        :initform nil :reader resolution-bytes)
   (status       :initarg :status       :initform :ok :reader resolution-status
                 :documentation
                 "Where it stopped: :OK, :NO-MANIFEST (this npub has published no
site), :NO-PATH (the site exists but does not have this path), or :NO-BLOB (the site
names a blob no server would give us).  This names the FIRST hop that broke."))
  (:documentation "The result of resolving one path of one nsite — every hop's
outcome, not just the bytes, so a failure says which hop failed."))

(defmethod print-object ((r nsite-resolution) stream)
  (print-unreadable-object (r stream :type t)
    (format stream "~a ~a ~a~@[ ~d bytes~]" (resolution-npub r) (resolution-path r)
            (resolution-status r) (and (resolution-bytes r) (length (resolution-bytes r))))))

(defun resolution-ok-p (resolution) (eq (resolution-status resolution) :ok))

(defun nsite-resolve (where who path
                      &key servers (timeout 5) (legacy t) (fetch t)
                           (blob-timeout blossom:*blossom-timeout*))
  "Resolve PATH on the nsite published by WHO — an npub, nprofile, or hex pubkey — the
way a gateway would.  WHERE is a POOL, a list of relay urls, or NIL for
*DISCOVERY-RELAYS*; nothing else is needed, and no secret is involved.

Reads the newest kind-15128 manifest, looks PATH up in it (falling back to the
directory index, so \"/\" finds \"/index.html\"), then fetches that blob from the
site's own `server' hints and kind-10063 list — SERVERS, if given, is tried first —
VERIFYING each body against the hash, so a mirror serving the wrong bytes is a
failure and not a result.  :FETCH NIL stops after the hash, for callers that only
want to know what the site claims.

LEGACY (default true) falls back to the deprecated kind-34128 per-path events when
the manifest does not have the path.  Some gateways still read them, so a resolver
that ignored them would report \"not found\" for a path that is in fact being served
— a false negative on the exact question this function exists to answer.  The
manifest always wins when it has an answer, and RESOLUTION-SOURCE says which
answered.

Returns an NSITE-RESOLUTION.  It is not an error for a site not to have a path;
inspect RESOLUTION-STATUS."
  (%with-pool (pool where)
    (let* ((pubkey (%pubkey who))
           (npub (b:npub-encode pubkey))
           (manifest (nsite-fetch-manifest pool pubkey :timeout timeout)))
      (multiple-value-bind (hash matched)
          (if manifest (manifest-lookup manifest path) (values nil nil))
        (let ((source (and hash :manifest)))
          ;; the legacy format is a FALLBACK, never a merge: 15128 is what publishers
          ;; write, so it must win wherever it has an answer at all.
          (when (and (null hash) legacy)
            (let ((pointers (nsite-fetch-legacy pool pubkey :timeout timeout)))
              (dolist (candidate (%path-candidates path))
                (let ((hit (assoc candidate pointers :test #'string=)))
                  (when hit
                    (setf hash (cdr hit) matched (car hit) source :legacy)
                    (return))))))
          (flet ((result (&rest args)
                   (apply #'make-instance 'nsite-resolution
                          :npub npub :pubkey pubkey :path path :manifest manifest
                          :matched-path matched :hash hash :source source args)))
            (cond
              ((and (null hash) (null manifest)) (result :status :no-manifest))
              ((null hash)                       (result :status :no-path))
              ((not fetch)                       (result :status :ok))
              (t
               (let ((servers (remove-duplicates
                               (append (if (listp servers) servers (list servers))
                                       (nsite-servers pool pubkey :manifest manifest
                                                                  :timeout timeout))
                               :test #'string= :from-end t)))
                 (multiple-value-bind (bytes fetches)
                     (blossom:blossom-download-any (remove nil servers) hash
                                                   :timeout blob-timeout)
                   (result :servers servers :fetches fetches :bytes bytes
                           :server (let ((hit (find-if #'blossom:fetch-ok-p fetches)))
                                     (and hit (blossom:fetch-source hit)))
                           :status (if bytes :ok :no-blob))))))))))))

;;; ---- gateways -------------------------------------------------------------
;;; What a browser sees, which is not always what the relays hold: gateways cache,
;;; and two of them will happily disagree about the same npub for hours.

(defparameter *gateway* "nsite.lol"
  "Default nsite gateway host, serving <npub>.<gateway>/<path>.")

(defun nsite-gateway-url (who path &key (gateway *gateway*))
  "The URL a browser would use: https://<npub>.<gateway><path>."
  (format nil "https://~a.~a~a" (%npub who) gateway
          (if (and (plusp (length path)) (char= (char path 0) #\/))
              path
              (concatenate 'string "/" path))))

(defun nsite-gateway-fetch (who path &key (gateway *gateway*) expect
                                          (timeout blossom:*blossom-timeout*))
  "GET PATH for WHO through GATEWAY and hash what comes back.  EXPECT, if given, is
the blob hash it should be — that comparison is the whole point, because a gateway
serving a stale manifest returns HTTP 200 and looks perfectly healthy.  Returns a
BLOB-FETCH; never signals."
  (blossom:blossom-fetch (nsite-gateway-url who path :gateway gateway)
                         :expect expect :timeout timeout))

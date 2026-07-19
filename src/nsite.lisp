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

(in-package #:cl-nostr.nsite)

(defconstant +kind-nsite-root+ 15128
  "NIP-5A root-site manifest (path->blob), a replaceable event, one per pubkey.")
(defconstant +kind-nsite-legacy+ 34128
  "Legacy per-path nsite pointer (deprecated; prefer the kind-15128 manifest).")

(defun nsite-manifest (keypair paths &key servers title description)
  "Build and return a NIP-5A kind-15128 root-site manifest event.  PATHS is a list of
(path . sha256-hex) conses; SERVERS an optional list of Blossom server URLs hinting where the
blobs live; TITLE/DESCRIPTION optional site metadata.  Signed by KEYPAIR — hand it to
POOL-PUBLISH."
  (ev:build-event keypair +kind-nsite-root+ ""
    :tags (append (mapcar (lambda (p) (list "path" (car p) (cdr p))) paths)
                  (mapcar (lambda (s) (list "server" s)) servers)
                  (when title       (list (list "title" title)))
                  (when description (list (list "description" description))))))

(defun nsite-put (pool keypair path hash)
  "LEGACY (kind 34128): publish one replaceable path->blob pointer, tags (\"d\" PATH)
(\"x\" HASH).  Prefer NSITE-PUBLISH / NSITE-MANIFEST (kind 15128) for new sites.  Returns
the event."
  (let ((event (ev:build-event keypair +kind-nsite-legacy+ ""
                               :tags (list (list "d" path) (list "x" hash)))))
    (pool:pool-publish pool event)
    event))

(defun nsite-publish (pool blossom-server keypair files &key servers title description)
  "Publish a whole static site (NIP-5A, kind 15128).  FILES is a list of (PATH . OCTETS)
conses; each file's bytes are uploaded to BLOSSOM-SERVER, then ONE root-site manifest mapping
every PATH to its blob hash is published via POOL.  SERVERS (default: just BLOSSOM-SERVER) are
the Blossom hints written into the manifest; TITLE/DESCRIPTION optional.  Returns the site's
npub, under which a gateway (e.g. <npub>.nsite.lol) serves it.  Publish the author's kind-10063
(Blossom server list) and kind-10002 (relay list) too so gateways can discover both."
  (let ((paths (mapcar (lambda (file)
                         (destructuring-bind (path . octets) file
                           (let ((hash (blossom:blossom-upload blossom-server octets keypair)))
                             (format t "~&nsite: ~a -> ~a~%" path hash)
                             (cons path hash))))
                       files)))
    (pool:pool-publish pool
                       (nsite-manifest keypair paths
                                       :servers (or servers (list blossom-server))
                                       :title title :description description))
    (b:npub-encode (k:public-hex keypair))))

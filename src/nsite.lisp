;;;; src/nsite.lisp — nsite: a static website addressed by a Nostr pubkey.
;;;;
;;;; An nsite is a set of kind-34128 parameterized-replaceable events, one per
;;;; file path, that map a site path to a Blossom blob:
;;;;
;;;;   kind 34128, tags ("d" "/index.html") ("x" <sha256-hex>), content ""
;;;;
;;;; The `d' tag is the request path; the `x' tag is the SHA-256 of the file's
;;;; bytes, which is exactly the Blossom address of the uploaded blob.  A viewer
;;;; resolves <npub>.<gateway>/index.html by fetching the author's kind-34128
;;;; event with d="/index.html", reading its `x', and GETting that blob from a
;;;; Blossom server.  So publishing a site is: upload every file to Blossom,
;;;; then publish one kind-34128 pointer per path.

(in-package #:cl-nostr.nsite)

(defconstant +kind-nsite+ 34128
  "Parameterized-replaceable event kind for an nsite path->blob mapping.")

(defun nsite-put (pool keypair path hash)
  "Publish a kind-34128 event mapping site PATH (e.g. \"/index.html\") to the
Blossom blob whose SHA-256 hex is HASH.  Signs with KEYPAIR and publishes via
POOL.  Returns the event."
  (let ((event (ev:build-event keypair +kind-nsite+ ""
                               :tags (list (list "d" path)
                                           (list "x" hash)))))
    (pool:pool-publish pool event)
    event))

(defun nsite-publish (pool blossom-server keypair files)
  "Publish a whole static site.  FILES is a list of (PATH . OCTETS) conses; each
file's bytes are uploaded to BLOSSOM-SERVER, then a kind-34128 pointer for its
PATH is published via POOL.  Returns the site's npub (bech32 of KEYPAIR's
pubkey), under which the site is served."
  (dolist (file files)
    (destructuring-bind (path . octets) file
      (let ((hash (blossom:blossom-upload blossom-server octets keypair)))
        (format t "~&nsite: ~a -> ~a~%" path hash)
        (nsite-put pool keypair path hash))))
  (b:npub-encode (k:public-hex keypair)))

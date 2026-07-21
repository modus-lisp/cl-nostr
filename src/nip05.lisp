;;;; src/nip05.lisp — NIP-05: map a DNS-based identifier (name@domain) to a pubkey.
;;;;
;;;; A NIP-05 address like `alice@example.com' is resolved by GETting
;;;;   https://example.com/.well-known/nostr.json?name=alice
;;;; and reading names["alice"] -> 32-byte pubkey hex.  A bare domain resolves the
;;;; special name "_" (so `example.com' == `_@example.com').  The optional
;;;; relays[pubkey] list, when present, hints where that user posts.

(in-package #:cl-nostr.nip05)

(defun %split (address)
  "Split NAME@DOMAIN into (values NAME DOMAIN); a bare DOMAIN uses the name \"_\"."
  (let ((at (position #\@ address)))
    (if at
        (values (subseq address 0 at) (subseq address (1+ at)))
        (values "_" address))))

(defun nip05-address-p (s)
  "True if S looks like a NIP-05 identifier (has an @ with text on both sides, or a
bare dotted domain) rather than an npub/hex key."
  (and (stringp s)
       (let ((at (position #\@ s)))
         (and at (plusp at) (< (1+ at) (length s)) (find #\. s :start at)))))

(defun resolve (address &key (timeout 15))
  "Resolve NIP-05 ADDRESS (name@domain, or a bare domain) to (values PUBKEY-HEX RELAYS).
Fetches https://DOMAIN/.well-known/nostr.json?name=NAME and returns names[NAME] (or NIL
if the name isn't listed) plus any relays[pubkey] list.  Signals on network/HTTP error."
  (multiple-value-bind (name domain) (%split address)
    (let* ((url  (format nil "https://~a/.well-known/nostr.json?name=~a" domain name))
           (body (dexador:get url :connect-timeout timeout :read-timeout timeout
                                  :headers '(("Accept" . "application/json"))))
           (json (jzon:parse (if (stringp body) body (u:utf8->string body))))
           (names (and (hash-table-p json) (gethash "names" json)))
           (pubkey (and (hash-table-p names) (gethash name names)))
           (relays-map (and (hash-table-p json) (gethash "relays" json)))
           (relays (and (hash-table-p relays-map) pubkey (gethash pubkey relays-map))))
      (values pubkey (when relays (coerce relays 'list))))))

(defun resolve-pubkey (address &key (timeout 15))
  "Just the hex pubkey for NIP-05 ADDRESS, or NIL if unlisted."
  (values (resolve address :timeout timeout)))

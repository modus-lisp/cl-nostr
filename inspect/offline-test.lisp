;;;; inspect/offline-test.lisp — offline conformance gate (no network).
;;;;
;;;; Validates the pure layers against published, real-world vectors:
;;;;   - NIP-19 npub/nsec round-trips (the examples from the NIP-19 spec)
;;;;   - keypair derivation (nsec -> npub)
;;;;   - NIP-01 event id (byte-exact canonical serialization) + Schnorr verify,
;;;;     against the well-known "Walled gardens" event (fiatjaf, kind 1)
;;;;   - bech32 / TLV (nprofile/nevent) round-trips
;;;;   - filter JSON + local matching
;;;;
;;;;   sbcl --non-interactive --eval '(asdf:test-system "cl-nostr")'

(defpackage #:cl-nostr.test
  (:use #:cl)
  (:local-nicknames (#:u #:cl-nostr.util)
                    (#:k #:cl-nostr.keys)
                    (#:b #:cl-nostr.bech32)
                    (#:ev #:cl-nostr.event)
                    (#:flt #:cl-nostr.filter)
                    (#:pool #:cl-nostr.pool)
                    (#:blossom #:cl-nostr.blossom)
                    (#:nsite #:cl-nostr.nsite)
                    (#:nip44 #:cl-nostr.nip44)
                    (#:dr #:cl-nostr.double-ratchet)
                    (#:nip59 #:cl-nostr.nip59)
                    (#:udp #:cl-nostr.udp)
                    (#:nip44 #:cl-nostr.nip44)
                    (#:bt #:bordeaux-threads))
  (:export #:run))

(in-package #:cl-nostr.test)

(defvar *pass* 0)
(defvar *fail* 0)

(defun check (name got want &key (test #'equal))
  (if (funcall test got want)
      (progn (incf *pass*) (format t "  ok   ~a~%" name))
      (progn (incf *fail*)
             (format t "  FAIL ~a~%        got:  ~s~%        want: ~s~%" name got want))))

(defun check-true (name got)
  (if got (progn (incf *pass*) (format t "  ok   ~a~%" name))
      (progn (incf *fail*) (format t "  FAIL ~a (expected true)~%" name))))

;;; ---- NIP-19 spec vectors -------------------------------------------------

(defparameter +nsec+ "nsec1vl029mgpspedva04g90vltkh6fvh240zqtv9k0t9af8935ke9laqsnlfe5")
(defparameter +nsec-hex+ "67dea2ed018072d675f5415ecfaed7d2597555e202d85b3d65ea4e58d2d92ffa")
(defparameter +npub+ "npub10elfcs4fr0l0r8af98jlmgdh9c8tcxjvz9qkw038js35mp4dma8qzvjptg")
(defparameter +npub-hex+ "7e7e9c42a91bfef19fa929e5fda1b72e0ebc1a4c1141673e2794234d86addf4e")

(defun test-nip19 ()
  (format t "~%NIP-19 (spec vectors):~%")
  (check "nsec decode" (u:bytes->hex (b:nsec-decode +nsec+)) +nsec-hex+)
  (check "npub decode" (u:bytes->hex (b:npub-decode +npub+)) +npub-hex+)
  (check "nsec encode" (b:nsec-encode +nsec-hex+) +nsec+)
  (check "npub encode" (b:npub-encode +npub-hex+) +npub+)
  (let ((kp (k:keypair-from-secret +nsec-hex+)))
    (check "nsec -> npub derivation" (k:public-hex kp) +npub-hex+)))

;;; ---- NIP-01 event vector (fiatjaf "Walled gardens") ----------------------

(defparameter *walled-gardens*
  (list :id "4376c65d2f232afbe9b882a35baa4f6fe8667c4e684749af565f981833ed6a65"
        :pubkey "6e468422dfb74a5738702a8823b9b28168abab8655faacb6853cd0ee15deee93"
        :created-at 1673347337
        :kind 1
        :tags '(("e" "3da979448d9ba263864c4d6f14984c423a3838364ec255f03c7904b1ae77f206")
                ("p" "bf2376e17ba4ec269d10fcc996a4746b451152be9031fa48e74553dde5526bce"))
        :content "Walled gardens became prisons, and nostr is the first step towards tearing down the prison walls."
        :sig "908a15e46fb4d8675bab026fc230a0e3542bfade63da02d542fb78b2a8513fcd0092619a2c8c1221e581946e0191f2af505dfdf8657a414dbca329186f009262"))

(defun test-event ()
  (format t "~%NIP-01 event (real-world vector):~%")
  (destructuring-bind (&key id pubkey created-at kind tags content sig) *walled-gardens*
    ;; byte-exact canonical serialization: recomputed id must match
    (check "compute-id matches published id"
           (ev:compute-id pubkey created-at kind tags content) id)
    ;; Schnorr signature verifies under the x-only pubkey
    (check-true "signature verifies (verify-event)"
                (ev:verify-event (ev:make-event :id id :pubkey pubkey :created-at created-at
                                                :kind kind :tags tags :content content :sig sig)))
    ;; JSON round-trip preserves the id and stays verifiable
    (let* ((event (ev:make-event :id id :pubkey pubkey :created-at created-at
                                 :kind kind :tags tags :content content :sig sig))
           (round (ev:json->event (ev:event->json event))))
      (check "json round-trip preserves id" (ev:event-id round) id)
      (check-true "json round-trip still verifies" (ev:verify-event round))
      (check "e-tags helper" (ev:e-tags round)
             '("3da979448d9ba263864c4d6f14984c423a3838364ec255f03c7904b1ae77f206")))))

(defun test-sign-roundtrip ()
  (format t "~%Sign / verify round-trip (own keypair):~%")
  (let* ((kp (k:keypair-from-secret +nsec-hex+))
         (event (ev:build-event kp 1 "héllo, nostr — \"quotes\" & \\backslash\\"
                                :tags '(("t" "test")) :created-at 1700000000)))
    (check-true "freshly built event verifies" (ev:verify-event event))
    (check "author pubkey is npub-hex" (ev:event-pubkey event) +npub-hex+)
    ;; tamper: flip content, signature must now fail
    (let ((bad (ev:make-event :id (ev:event-id event) :pubkey (ev:event-pubkey event)
                              :created-at (ev:event-created-at event) :kind 1
                              :tags (ev:event-tags event) :content "tampered"
                              :sig (ev:event-sig event))))
      (check-true "tampered event fails verify" (not (ev:valid-event-p bad))))))

(defun test-tlv-spec ()
  "Decode the canonical nprofile from the NIP-19 spec."
  (format t "~%NIP-19 TLV (spec vector):~%")
  (multiple-value-bind (pk relays)
      (b:nprofile-decode
       "nprofile1qqsrhuxx8l9ex335q7he0f09aej04zpazpl0ne2cgukyawd24mayt8gpp4mhxue69uhhytnc9e3k7mgpz4mhxue69uhkg6nzv9ejuumpv34kytnrdaksjlyr9p")
    (check "spec nprofile pubkey" (u:bytes->hex pk)
           "3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d")
    (check "spec nprofile relays" relays '("wss://r.x.com" "wss://djbas.sadkb.com"))))

(defun test-tlv ()
  (format t "~%NIP-19 TLV round-trips:~%")
  (let* ((pk +npub-hex+)
         (relays '("wss://relay.example.com" "wss://nos.lol")))
    (multiple-value-bind (dpk drelays) (b:nprofile-decode (b:nprofile-encode pk :relays relays))
      (check "nprofile pubkey" (u:bytes->hex dpk) pk)
      (check "nprofile relays" drelays relays))
    (multiple-value-bind (id drelays author kind)
        (b:nevent-decode (b:nevent-encode (getf *walled-gardens* :id)
                                          :relays '("wss://relay.damus.io")
                                          :author pk :kind 1))
      (check "nevent id" (u:bytes->hex id) (getf *walled-gardens* :id))
      (check "nevent relays" drelays '("wss://relay.damus.io"))
      (check "nevent author" (u:bytes->hex author) pk)
      (check "nevent kind" kind 1))))

(defun test-filter ()
  (format t "~%Filters:~%")
  (let ((f (flt:make-filter :authors (list +npub-hex+) :kinds '(1)
                            :tags '(("t" . ("test"))) :limit 10)))
    (check "filter->json"
           (flt:filter->json f)
           (format nil "{\"authors\":[~s],\"kinds\":[1],\"#t\":[\"test\"],\"limit\":10}" +npub-hex+))
    (let ((event (ev:build-event (k:keypair-from-secret +nsec-hex+) 1 "x"
                                 :tags '(("t" "test")) :created-at 1700000000)))
      (check-true "filter matches event" (flt:filter-matches-p f event))
      (check-true "filter rejects wrong kind"
                  (not (flt:filter-matches-p (flt:make-filter :kinds '(7)) event))))))

;;; ---- nsite (NIP-5A): manifest construction and tag round-trips -----------
;;; The manifest IS the site: every path a reader can reach is a tag in it, so a
;;; path that does not survive the round trip is a page that 404s.

(defparameter +hash-a+ "8f434346648f6b96df89dda901c5176b10a6d83961dd3c1ac88b59b2dc327aa4")
(defparameter +hash-b+ "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")

(defun test-nsite-manifest ()
  (format t "~%nsite manifest (NIP-5A kind 15128):~%")
  (let* ((kp (k:keypair-from-secret +nsec-hex+))
         (paths (list (cons "/k30.html" +hash-a+)
                      (cons "/index.html" +hash-a+)
                      (cons "/style.css" +hash-b+)))
         (servers '("https://cdn.hzrd149.com" "https://blossom.primal.net"))
         (manifest (nsite:nsite-manifest kp paths :servers servers :title "a site"
                                                  :description "hello")))
    (check "manifest kind is 15128" (ev:event-kind manifest) nsite:+kind-nsite-root+)
    (check-true "manifest is signed and verifies" (ev:verify-event manifest))
    ;; path/hash tags round-trip: what went in is what a reader gets back out
    (check "path tags round-trip" (nsite:manifest-paths manifest) paths)
    (check "server tags round-trip" (nsite:manifest-servers manifest) servers)
    (check "title round-trip" (nsite:manifest-title manifest) "a site")
    (check "description round-trip" (nsite:manifest-description manifest) "hello")
    ;; lookup is what a gateway does, including the directory-index rule
    (check "lookup exact path" (nsite:manifest-lookup manifest "/style.css") +hash-b+)
    (check "lookup relative path gets a leading slash"
           (nsite:manifest-lookup manifest "k30.html") +hash-a+)
    (multiple-value-bind (hash matched) (nsite:manifest-lookup manifest "/")
      (check "lookup \"/\" falls back to the directory index" hash +hash-a+)
      (check "lookup \"/\" reports the path it matched" matched "/index.html"))
    (check "lookup of a path the site does not have"
           (nsite:manifest-lookup manifest "/nope.html") nil)))

(defun test-nsite-legacy ()
  (format t "~%nsite legacy pointer (kind 34128):~%")
  (let* ((kp (k:keypair-from-secret +nsec-hex+))
         (event (ev:build-event kp nsite:+kind-nsite-legacy+ ""
                                :tags (list (list "d" "/index.html") (list "x" +hash-a+)))))
    (check "d/x tags round-trip" (nsite:legacy-pointer event) (cons "/index.html" +hash-a+))
    (check "a kind-1 note is not a pointer"
           (nsite:legacy-pointer (ev:build-event kp 1 "hi")) nil)))

(defun test-nsite-discovery-lists ()
  (format t "~%nsite discovery lists:~%")
  (let* ((kp (k:keypair-from-secret +nsec-hex+))
         (relays '("wss://relay.damus.io" "wss://nos.lol"))
         (servers '("https://cdn.hzrd149.com")))
    (let ((event (nsite:relay-list-event kp relays)))
      (check "relay list is kind 10002" (ev:event-kind event) 10002)
      (check "relay list r tags" (ev:tag-values event "r") relays))
    (let ((event (nsite:server-list-event kp servers)))
      (check "server list is kind 10063" (ev:event-kind event) 10063)
      (check "server list server tags" (ev:tag-values event "server") servers))))

(defun test-nsite-blob-grouping ()
  "Blossom is content-addressed, so paths sharing bytes share ONE upload."
  (format t "~%nsite blob grouping:~%")
  (multiple-value-bind (paths blobs)
      (cl-nostr.nsite::%blobs (list (cons "/a.html" "same") (cons "/b.html" "same")
                                    (cons "/c.css" "other"))
                              nil)
    (check "every path is mapped" (mapcar #'car paths) '("/a.html" "/b.html" "/c.css"))
    (check "paths with the same bytes get the same hash"
           (equal (cdr (first paths)) (cdr (second paths))) t)
    (check "distinct blobs, not distinct paths" (length blobs) 2)
    (check "content type guessed from the first path naming the blob"
           (third (first blobs)) "text/html")
    (check "content type of the second blob" (third (second blobs)) "text/css"))
  (multiple-value-bind (paths blobs)
      (cl-nostr.nsite::%blobs (list (cons "/" "x")) "text/html")
    (declare (ignore paths))
    (check "an explicit content type overrides the guess" (third (first blobs)) "text/html")))

;;; ---- partial outcomes ----------------------------------------------------
;;; Some servers down and some relays refusing is the NORMAL case, so the report
;;; has to distinguish "a peer declined" from "this did not get published".

(defun %upload (server hash &key ok error)
  (make-instance 'blossom:blob-upload :server server :hash hash :ok ok :error error))

(defun %ack (url status &optional message)
  (make-instance 'pool:relay-ack :url url :event-id "id" :status status :message message))

(defun %report (paths uploads &optional publications)
  (make-instance 'nsite:nsite-report :npub "npub1test" :pubkey "ff"
                                     :paths paths :uploads uploads
                                     :publications publications))

(defun %manifest-publication (acks)
  (make-instance 'nsite:publication
                 :event (ev:build-event (k:keypair-from-secret +nsec-hex+)
                                        nsite:+kind-nsite-root+ "")
                 :acks acks))

(defun test-ack-status ()
  (format t "~%relay acks:~%")
  (check-true "accepted counts as accepted" (pool:ack-accepted-p (%ack "wss://a" :accepted)))
  (check-true "rejected is a reply, not an acceptance"
              (and (pool:ack-replied-p (%ack "wss://a" :rejected))
                   (not (pool:ack-accepted-p (%ack "wss://a" :rejected)))))
  (dolist (status '(:no-reply :send-failed :unreachable))
    (check-true (format nil "~a is neither a reply nor an acceptance" status)
                (not (or (pool:ack-replied-p (%ack "wss://a" status))
                         (pool:ack-accepted-p (%ack "wss://a" status))))))
  (check "acks-accepted keeps only the acceptances"
         (mapcar #'pool:ack-url
                 (pool:acks-accepted (list (%ack "wss://a" :accepted)
                                           (%ack "wss://b" :rejected "blocked: policy")
                                           (%ack "wss://c" :unreachable)
                                           (%ack "wss://d" :accepted))))
         '("wss://a" "wss://d")))

(defun test-partial-publish-report ()
  (format t "~%partial publish outcomes:~%")
  ;; one server took the blob, one timed out, one refused: that is a SUCCESS
  (let ((report (%report (list (cons "/index.html" +hash-a+))
                         (list (%upload "https://one" +hash-a+ :ok t)
                               (%upload "https://two" +hash-a+ :error "no answer within 45 s")
                               (%upload "https://three" +hash-a+ :error "HTTP 402"))
                         (list (%manifest-publication
                                (list (%ack "wss://a" :accepted)
                                      (%ack "wss://b" :rejected "blocked: policy")
                                      (%ack "wss://c" :unreachable)))))))
    (check-true "one good mirror means the blob is stored" (nsite:report-stored-p report))
    (check-true "one accepting relay means it is published" (nsite:report-published-p report))
    (check "a partial publish reports no problems" (nsite:report-problems report) '())
    (check-true "and is ok" (nsite:report-ok-p report))
    (check "every server's attempt is still visible"
           (length (nsite:report-blob-uploads report +hash-a+)) 3)
    (check "the manifest publication is findable by kind"
           (nsite:publication-kind (nsite:report-manifest report)) 15128)
    (check "and names the relay that took it"
           (mapcar #'pool:ack-url (nsite:publication-accepted (nsite:report-manifest report)))
           '("wss://a")))
  ;; every relay refused: nothing was published, however healthy it looked
  (let ((report (%report (list (cons "/index.html" +hash-a+))
                         (list (%upload "https://one" +hash-a+ :ok t))
                         (list (%manifest-publication
                                (list (%ack "wss://a" :rejected "blocked")
                                      (%ack "wss://b" :no-reply)))))))
    (check-true "zero acceptances means NOT published" (not (nsite:report-published-p report)))
    (check "and says so" (nsite:report-problems report) '("no relay accepted the manifest")))
  ;; no server took the blob: the manifest must not be published at all
  (let ((report (%report (list (cons "/index.html" +hash-a+) (cons "/b.css" +hash-b+))
                         (list (%upload "https://one" +hash-a+ :ok t)
                               (%upload "https://one" +hash-b+ :error "HTTP 500")))))
    (check-true "a blob no server took is not stored" (not (nsite:report-stored-p report)))
    (check-true "even though the other blob was" (nsite:report-stored-p report +hash-a+))
    (check "the unstored blob is named, and so is the missing manifest"
           (nsite:report-problems report)
           (list (format nil "no Blossom server stored ~a" (subseq +hash-b+ 0 16))
                 "the manifest was never published"))
    (check-true "so the publish is not ok" (not (nsite:report-ok-p report)))))

(defun test-resolution-status ()
  (format t "~%resolution status (which hop broke):~%")
  (flet ((res (&rest args)
           (apply #'make-instance 'nsite:nsite-resolution
                  :npub "npub1test" :pubkey "ff" :path "/index.html" args)))
    (check-true "ok resolves" (nsite:resolution-ok-p (res :status :ok)))
    (dolist (status '(:no-manifest :no-path :no-blob))
      (check-true (format nil "~a does not" status)
                  (not (nsite:resolution-ok-p (res :status status)))))))

(defun test-gateway-url ()
  (format t "~%gateway urls:~%")
  (check "npub + path -> a browser url"
         (nsite:nsite-gateway-url +npub+ "/k30.html" :gateway "nsite.lol")
         (format nil "https://~a.nsite.lol/k30.html" +npub+))
  (check "a hex pubkey is accepted too"
         (nsite:nsite-gateway-url +npub-hex+ "index.html" :gateway "nsite.run")
         (format nil "https://~a.nsite.run/index.html" +npub+)))

(defun test-deadline ()
  (format t "~%deadlines (no request may be unbounded):~%")
  (multiple-value-bind (value condition timed-out) (u:call-with-deadline 5 (lambda () 42))
    (check "a prompt thunk returns its value" value 42)
    (check-true "with no condition and no timeout" (and (null condition) (null timed-out))))
  (multiple-value-bind (value condition timed-out)
      (u:call-with-deadline 5 (lambda () (error "nope")))
    (check-true "a signalling thunk is caught, not propagated"
                (and (null value) condition (null timed-out))))
  (multiple-value-bind (value condition timed-out)
      (u:call-with-deadline 0.5 (lambda () (sleep 30) :never))
    (check-true "a hanging thunk is abandoned on the clock"
                (and (null value) (null condition) timed-out)))
  (let ((results (u:call-in-parallel 3 (list (lambda () :a)
                                             (lambda () (sleep 30) :b)
                                             (lambda () :c)))))
    (check "one hung thunk does not lose the others"
           (mapcar #'first results) '(:a nil :c))
    (check-true "and is reported as timed out" (third (second results)))))

(defun test-concurrent-signing ()
  "secp256k1-fast is not thread-safe; CL-NOSTR.KEYS serializes it.  Without that lock
this test signals in most threads and returns INVALID signatures from the rest — the
failure that makes a good key look like a bad one to a relay."
  (format t "~%Concurrent signing (a pool and an uploader both fan out):~%")
  (let ((kp (k:keypair-from-secret +nsec-hex+))
        (bad 0) (errors 0) (signed 0)
        (lock (bt:make-lock "test")))
    (dotimes (round 10)
      (let ((threads (loop repeat 4
                           collect (bt:make-thread
                                    (lambda ()
                                      (handler-case
                                          (let ((event (ev:build-event kp 1 "concurrent")))
                                            (bt:with-lock-held (lock)
                                              (incf signed)
                                              (unless (ev:verify-event event) (incf bad))))
                                        (serious-condition ()
                                          (bt:with-lock-held (lock) (incf errors)))))))))
        (dolist (th threads) (ignore-errors (bt:join-thread th)))))
    (check "every concurrent signature was produced" signed 40)
    (check "none signalled" errors 0)
    (check "and every one verifies" bad 0)))

(defun test-nip59-rumor ()
  "General NIP-59 rumors: any kind and tags survive, the receiver gets the whole
unsigned rumor, and a wrap for someone else is refused."
  (format t "~&~%NIP-59 general rumors:~%")
  (let* ((alice (k:generate-keypair))
         (bob (k:generate-keypair))
         (wrap (nip59:wrap-rumor alice (k:public-hex bob) 444 "welcome bytes"
                                 :tags '(("e" "00ff") ("relays" "wss://a" "wss://b"))
                                 :created-at 1700000000)))
    (check "wrap is kind 1059" (ev:event-kind wrap) 1059)
    (check-true "wrap verifies" (ev:verify-event wrap))
    (multiple-value-bind (rumor seal) (nip59:unwrap-rumor bob (ev:json->event (ev:event->json wrap)))
      (check "rumor kind" (ev:event-kind rumor) 444)
      (check "rumor tags" (ev:event-tags rumor) '(("e" "00ff") ("relays" "wss://a" "wss://b")))
      (check "rumor content" (ev:event-content rumor) "welcome bytes")
      (check "rumor created_at" (ev:event-created-at rumor) 1700000000)
      (check "rumor author is the seal signer" (ev:event-pubkey rumor) (ev:event-pubkey seal))
      (check "rumor author is alice" (ev:event-pubkey rumor) (k:public-hex alice))
      (check "rumor is unsigned" (ev:event-sig rumor) nil))
    (check-true "a wrap for bob is refused to alice"
                (handler-case (progn (nip59:unwrap-rumor alice wrap) nil) (error () t)))))

(defun nip44-section (section &optional (kind "valid"))
  "A section of the official NIP-44 v2 vectors (inspect/nip44.vectors.json)."
  (let ((root (json-simple:parse (uiop:read-file-string
                                  (asdf:system-relative-pathname "cl-nostr" "inspect/nip44.vectors.json")))))
    (gethash section (gethash kind (gethash "v2" root)))))

(defun test-nip44-vectors ()
  "NIP-44 v2 against the official vectors, both directions: padding, conversation and
message keys, encryptions byte-exact under the vector's own nonce, long messages by hash,
the lengths that must be refused, and the payloads that must be refused."
  (format t "~&-- NIP-44 v2, official vectors --~%")
  (let ((pads (nip44-section "calc_padded_len")))
    (check-true (format nil "padded lengths (~d)" (length pads))
                (every (lambda (p) (= (aref p 1) (nip44:calc-padded-len (aref p 0)))) pads)))
  (let ((rows (nip44-section "get_conversation_key")))
    (check-true (format nil "conversation keys (~d)" (length rows))
                (every (lambda (r)
                         (let* ((kp (k:keypair-from-secret (gethash "sec1" r)))
                                (ck (nip44:conversation-key kp (u:hex->bytes (gethash "pub2" r)))))
                           (prog1 (equalp ck (u:hex->bytes (gethash "conversation_key" r)))
                             (gossamer:free ck) (k:keypair-wipe kp))))
                       rows)))
  (let* ((section (nip44-section "get_message_keys"))
         (ck (u:hex->bytes (gethash "conversation_key" section)))
         (keys (gethash "keys" section)))
    (check-true (format nil "message keys (~d)" (length keys))
                (every (lambda (k)
                         (nip44::with-message-keys (ck-key ck-nonce hmac-key)
                             ck (u:hex->bytes (gethash "nonce" k))
                           (and (equalp ck-key (u:hex->bytes (gethash "chacha_key" k)))
                                (equalp ck-nonce (u:hex->bytes (gethash "chacha_nonce" k)))
                                (equalp hmac-key (u:hex->bytes (gethash "hmac_key" k))))))
                       keys)))
  (let ((rows (nip44-section "encrypt_decrypt")))
    (check-true (format nil "encryptions, byte-exact under the vector nonce (~d)" (length rows))
                (every (lambda (r)
                         (string= (nip44:nip44-encrypt-with-nonce
                                   (u:string->utf8 (gethash "plaintext" r))
                                   (u:hex->bytes (gethash "conversation_key" r))
                                   (u:hex->bytes (gethash "nonce" r)))
                                  (gethash "payload" r)))
                       rows))
    (check-true "and they decrypt"
                (every (lambda (r)
                         (string= (nip44:nip44-decrypt-ck (gethash "payload" r)
                                                          (u:hex->bytes (gethash "conversation_key" r)))
                                  (gethash "plaintext" r)))
                       rows)))
  (let ((long (nip44-section "encrypt_decrypt_long_msg")))
    (check-true (format nil "long messages, by hash (~d)" (length long))
                (every (lambda (r)
                         (let* ((pattern (gethash "pattern" r))
                                (text (with-output-to-string (out)
                                        (dotimes (i (gethash "repeat" r)) (write-string pattern out))))
                                (plain (u:string->utf8 text))
                                (payload (nip44:nip44-encrypt-with-nonce
                                          plain (u:hex->bytes (gethash "conversation_key" r))
                                          (u:hex->bytes (gethash "nonce" r)))))
                           (and (string= (u:bytes->hex (u:sha256 plain)) (gethash "plaintext_sha256" r))
                                (string= (u:bytes->hex (u:sha256 (u:string->utf8 payload)))
                                         (gethash "payload_sha256" r)))))
                       long)))
  (let ((lengths (nip44-section "encrypt_msg_lengths" "invalid")))
    (check-true (format nil "lengths out of range refused (~d)" (length lengths))
                (every (lambda (n)
                         (handler-case (progn (nip44:nip44-encrypt-with-nonce
                                               (make-array n :element-type '(unsigned-byte 8)
                                                             :initial-element 65)
                                               (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)
                                               (u:random-bytes 32))
                                              nil)
                           (error () t)))
                       lengths)))
  (let ((rows (nip44-section "decrypt" "invalid")))
    (check-true (format nil "all ~d invalid payloads refused" (length rows))
                (every (lambda (r)
                         (handler-case (progn (nip44:nip44-decrypt-ck (gethash "payload" r)
                                                                      (u:hex->bytes (gethash "conversation_key" r)))
                                              nil)
                           (error () t)))
                       rows))))

(defun test-udp-encrypted ()
  "The encrypted datagram: opened by the relay to the same event, unreadable to anyone
else, refused when altered, and delivered over a real loopback socket."
  (format t "~&-- UDP datagrams, NIP-44 encrypted --~%")
  (let* ((relay (k:generate-keypair))
         (pub (k:public-hex relay))
         (kp (k:generate-keypair))
         (ev (ev:build-event kp 1 (format nil "sealed ☃ ~a" (code-char #x1F600))))
         (octets (udp:encrypted-datagram ev pub)))
    (check-true "encrypted datagram fits one unfragmented frame"
                (<= (length octets) udp:+max-datagram+))
    (check "the relay opens it to the same event"
           (ev:event-id (ev:json->event (u:utf8->string (udp:open-datagram relay octets))))
           (ev:event-id ev))
    (check-true "the opened event verifies"
                (ev:valid-event-p (ev:json->event (u:utf8->string (udp:open-datagram relay octets)))))
    (check-true "the content is not in the clear"
                (not (search (u:string->utf8 "sealed") octets)))
    (check-true "another key cannot open it"
                (handler-case (progn (udp:open-datagram (k:generate-keypair) octets) nil)
                  (error () t)))
    (check-true "an altered datagram is refused"
                (handler-case (let ((bad (copy-seq octets)))
                                (setf (aref bad (1- (length bad))) (logxor 1 (aref bad (1- (length bad)))))
                                (udp:open-datagram relay bad)
                                nil)
                  (error () t)))
    (check-true "an event past the bound is refused"
                (handler-case (progn (udp:encrypted-datagram
                                      (ev:build-event kp 1 (make-string 2000 :initial-element #\x)) pub)
                                     nil)
                  (udp:datagram-too-large () t)))
    (check-true "the ephemeral key never begins with '{' (60 datagrams)"
                (loop repeat 60 never (= #x7b (aref (udp:encrypted-datagram ev pub) 0))))
    (let ((rx (cl-transport.sockets:udp-open :admit (constantly t))))
      (unwind-protect
           (progn
             (check "publish-datagram-encrypted returns the id"
                    (udp:publish-datagram-encrypted "127.0.0.1" (cl-transport.sockets:udp-local-port rx)
                                                    ev pub)
                    (ev:event-id ev))
             (let ((peer (cl-transport.sockets:udp-accept rx :timeout-ms 2000)))
               (check-true "loopback receiver sees the encrypted datagram" peer)
               (when peer
                 (multiple-value-bind (got status)
                     (cl-transport.sockets:udp-peer-read
                      peer (+ (get-internal-real-time) (* 2 internal-time-units-per-second)))
                   (check "the receiver opens it to the event"
                          (and (eq status :ok)
                               (ev:event-id (ev:json->event (u:utf8->string (udp:open-datagram relay got)))))
                          (ev:event-id ev))))))
        (cl-transport.sockets:udp-close rx)))))

(defun test-udp ()
  "One event as one datagram: the bytes parse back to the same signed event, the
size bound refuses what would fragment, and a loopback receiver gets the bytes."
  (format t "~&-- UDP datagrams --~%")
  (let* ((kp (k:generate-keypair))
         (ev (ev:build-event kp 1 (format nil "naïve ☃ ~a" (code-char #x1F600))))
         (octets (udp:event->datagram ev))
         (back (ignore-errors (ev:json->event (u:utf8->string octets)))))
    (check-true "datagram fits one unfragmented frame" (<= (length octets) udp:+max-datagram+))
    (check "datagram parses back to the same event id"
           (and back (ev:event-id back)) (ev:event-id ev))
    (check-true "the datagram's event verifies" (and back (ev:valid-event-p back)))
    (check-true "an event past the bound is refused"
                (handler-case (progn (udp:event->datagram
                                      (ev:build-event kp 1 (make-string 2000 :initial-element #\x)))
                                     nil)
                  (udp:datagram-too-large (c) (> (udp:datagram-size c) udp:+max-datagram+))))
    ;; a real receiver on loopback: admit every stranger, read the datagram back
    (let ((rx (cl-transport.sockets:udp-open :admit (constantly t))))
      (unwind-protect
           (let ((id (udp:publish-datagram "127.0.0.1" (cl-transport.sockets:udp-local-port rx) ev)))
             (check "publish-datagram returns the event id" id (ev:event-id ev))
             (let ((peer (cl-transport.sockets:udp-accept rx :timeout-ms 2000)))
               (check-true "loopback receiver sees the datagram" peer)
               (when peer
                 (multiple-value-bind (got status)
                     (cl-transport.sockets:udp-peer-read
                      peer (+ (get-internal-real-time) (* 2 internal-time-units-per-second)))
                   (check "received bytes are the datagram"
                          (and (eq status :ok) (equalp got octets)) t)))))
        (cl-transport.sockets:udp-close rx)))))
(defun test-nip44-gossamer-keys ()
  "NIP-44 with the private keys as gossamer secrets: the conversation key comes back
in non-moving memory, the keypair path agrees with the vectors, and an integer key
is refused."
  (format t "~&~%NIP-44 with gossamer keys:~%")
  (flet ((kp (hex) (k:keypair-from-secret hex)))
    (let ((ck (nip44:conversation-key (kp "315e59ff51cb9209768cf7da80791ddcaae56ac9775eb25b6dee1234bc5d2268")
                                      (u:hex->bytes "c2f9d9948dc8c7c38321e4b85c8558872eafa0641cd269db76848a6073e69133"))))
      (check "conversation key (vector 0)" (u:bytes->hex ck)
             "3dfef0ce2a4d80a25e7a328accf73448ef67096f65f79588e358d9a0eb9013f1")
      (check-true "conversation key is in fixed memory" (gossamer:fixed-p ck)))
    (let* ((a (kp "0000000000000000000000000000000000000000000000000000000000000001"))
           (b (kp "0000000000000000000000000000000000000000000000000000000000000002"))
           (ck (nip44:conversation-key a (k:keypair-public-key b)))
           (nonce (u:hex->bytes "0000000000000000000000000000000000000000000000000000000000000001"))
           (payload (nip44:nip44-encrypt-with-nonce (u:string->utf8 "a") ck nonce)))
      (check "encrypt conversation key" (u:bytes->hex ck)
             "c41c775356fd92eadc63ff5a0dc1da211b268cbea22316767095b2871ea1412d")
      (check "encrypt payload (vector 0)" payload
             "AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABee0G5VSK0/9YypIObAtDKfYEAjD35uVkHyB0F4DwrcNaCXlCWZKaArsGrY6M9wnuTMxWfp1RTN9Xga8no+kF5Vsb")
      (check "decrypt payload" (nip44:nip44-decrypt-ck payload ck) "a")
      (check "decrypt via the peer's key" (nip44:nip44-decrypt b (k:public-hex a) (nip44:nip44-encrypt a (k:public-hex b) "hello")) "hello"))
    (check-true "an integer secret is refused"
                (handler-case (progn (nip44:nip44-encrypt 1 (make-string 64 :initial-element #\0) "x") nil) (error () t)))))

(defun test-double-ratchet ()
  "Two double-ratchet sessions talk: in order, out of order, after a persist/restore,
and every key buffer goes back to the pool when the sessions are freed."
  (format t "~&~%Double ratchet:~%")
  (let* ((free0 (nth-value 1 (gossamer:pool-stats)))
         (shared (gossamer:make-fixed-octets 32))
         (alice-eph (dr:gen-priv)) (bob-eph (dr:gen-priv)))
    (natrium:random-bytes-into shared)
    (let* ((alice (dr:dr-init (dr:priv->pub-hex bob-eph) alice-eph nil shared))   ; responder
           (bob   (dr:dr-init (dr:priv->pub-hex alice-eph) bob-eph t shared)))     ; sends first
      (flet ((text (rumor) (and rumor (gethash "content" rumor))))
        (let ((m1 (dr:dr-send-event bob "hi alice")))
          (check "first message decrypts" (text (dr:dr-receive-event alice m1)) "hi alice"))
        (check-true "the responder can now reply" (dr:dr-can-send-p alice))
        (check "reply decrypts" (text (dr:dr-receive-event bob (dr:dr-send-event alice "hi bob"))) "hi bob")
        (let ((a (dr:dr-send-event bob "one")) (b (dr:dr-send-event bob "two")) (c (dr:dr-send-event bob "three")))
          (check "out of order: third first" (text (dr:dr-receive-event alice c)) "three")
          (check "then the first (skipped key)" (text (dr:dr-receive-event alice a)) "one")
          (check "then the second (skipped key)" (text (dr:dr-receive-event alice b)) "two")
          (check "a replay is refused" (dr:dr-receive-event alice b) nil))
        (let ((json (dr:dr-state->json alice)))
          (dr:dr-free alice)
          (setf alice (dr:json->dr-state json))
          (check "after persist/restore the session still decrypts"
                 (text (dr:dr-receive-event alice (dr:dr-send-event bob "after restore"))) "after restore")
          (check "and still replies"
                 (text (dr:dr-receive-event bob (dr:dr-send-event alice "back at you"))) "back at you"))
        (check-true "a garbage event leaves the state intact"
                    (and (null (dr:dr-receive-event alice (dr:dr-send-event alice "to myself")))
                         (equal (text (dr:dr-receive-event alice (dr:dr-send-event bob "still fine"))) "still fine"))))
      (dr:dr-free alice) (dr:dr-free bob))
    (dr:dr-free-key alice-eph) (dr:dr-free-key bob-eph)
    (multiple-value-bind (allocated free) (gossamer:pool-stats)
      (declare (ignore allocated))
      (check-true "every key buffer went back to the pool" (>= free free0)))))

(defun run ()
  (setf *pass* 0 *fail* 0)
  (format t "~&=== cl-nostr offline gate ===~%")
  (test-nip19)
  (test-event)
  (test-sign-roundtrip)
  (test-tlv-spec)
  (test-tlv)
  (test-filter)
  (test-nsite-manifest)
  (test-nsite-legacy)
  (test-nsite-discovery-lists)
  (test-nsite-blob-grouping)
  (test-ack-status)
  (test-partial-publish-report)
  (test-resolution-status)
  (test-gateway-url)
  (test-deadline)
  (test-concurrent-signing)
  (test-nip59-rumor)
  (test-udp)
  (test-nip44-vectors)
  (test-nip44-gossamer-keys)
  (test-udp-encrypted)
  (test-double-ratchet)
  (format t "~%=== ~d passed, ~d failed ===~%" *pass* *fail*)
  (when (plusp *fail*) (error "cl-nostr offline gate: ~d failures" *fail*))
  t)

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
                    (#:flt #:cl-nostr.filter))
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

(defun run ()
  (setf *pass* 0 *fail* 0)
  (format t "~&=== cl-nostr offline gate ===~%")
  (test-nip19)
  (test-event)
  (test-sign-roundtrip)
  (test-tlv-spec)
  (test-tlv)
  (test-filter)
  (format t "~%=== ~d passed, ~d failed ===~%" *pass* *fail*)
  (when (plusp *fail*) (error "cl-nostr offline gate: ~d failures" *fail*))
  t)

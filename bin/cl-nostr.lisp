;;;; bin/cl-nostr.lisp — a small demo client.
;;;;
;;;; Generates (or restores) a keypair, connects to a few public relays, and
;;;; streams the live global feed of kind-1 notes, verifying each signature as it
;;;; arrives.  With an "nsec1..." argument it restores that identity instead of
;;;; generating a fresh one.
;;;;
;;;;   sbcl --load bin/cl-nostr.lisp [nsec1...]
;;;;
;;;; Set CL_NOSTR_RELAYS to a comma-separated list to override the relays.

(require :asdf)
(pushnew (uiop:pathname-parent-directory-pathname
          (uiop:pathname-directory-pathname (or *load-truename* *compile-file-truename*)))
         asdf:*central-registry* :test #'equal)
(handler-bind ((warning #'muffle-warning)) (asdf:load-system "cl-nostr"))

(in-package #:cl-nostr)

(defun split-commas (s)
  (loop with start = 0 for pos = (position #\, s :start start)
        collect (string-trim " " (subseq s start (or pos (length s))))
        while pos do (setf start (1+ pos))))

(defun main ()
  (let* ((arg (second sb-ext:*posix-argv*))
         (kp (if (and arg (>= (length arg) 4) (string= (subseq arg 0 4) "nsec"))
                 (keys:keypair-from-secret (bech32:nsec-decode arg))
                 (keys:make-keypair)))
         (relays (let ((env (sb-ext:posix-getenv "CL_NOSTR_RELAYS")))
                   (if env (split-commas env)
                       '("wss://relay.damus.io" "wss://nos.lol" "wss://relay.nostr.band")))))
    (format t "~&[cl-nostr] identity~%")
    (format t "  npub: ~a~%" (bech32:npub-encode (keys:public-hex kp)))
    (format t "  nsec: ~a   (keep this secret)~%" (bech32:nsec-encode (keys:secret-hex kp)))
    (format t "~%[cl-nostr] connecting to relays...~%")
    (let ((pool (pool:make-pool relays)))
      (format t "  connected to ~d/~d relays~%~%[cl-nostr] streaming global feed (Ctrl-C to quit)~%~%"
              (length (pool:pool-relays pool)) (length relays))
      (pool:pool-subscribe
       pool (filter:make-filter :kinds '(1) :limit 20)
       :on-event
       (lambda (event relay)
         (declare (ignore relay))
         (when (event:verify-event event)
           (let ((c (substitute #\Space #\Newline (event:event-content event))))
             (format t "~a │ ~a~%"
                     (subseq (event:event-pubkey event) 0 8)
                     (subseq c 0 (min 100 (length c))))
             (force-output)))))
      ;; park forever; the relay read threads do the work.
      (loop (sleep 60)))))

(main)

;;;; src/udp.lisp — one signed event as one UDP datagram, sent and not answered.
;;;;
;;;; The UDP path of the relay protocol (beacon's --udp-port; the design is
;;;; laantungir's "UDP nostr").  The event's own signature stands in for a handshake,
;;;; so the sender opens nothing and expects nothing.  A relay does not reply to a
;;;; datagram on any path -- accepted, refused or malformed -- so PUBLISH-DATAGRAM can
;;;; report that the bytes left this host, never that the event was stored.  Use the
;;;; WebSocket publish when the answer matters.
;;;;
;;;; The encrypted form (ENCRYPTED-DATAGRAM, PUBLISH-DATAGRAM-ENCRYPTED) seals the
;;;; event to the relay's public key: the datagram is a fresh ephemeral x-only pubkey
;;;; (32 bytes) then a NIP-44 v2 payload, so a passive observer learns neither the
;;;; content nor the author.  The relay opens it with its secret (beacon's
;;;; --udp-secret); OPEN-DATAGRAM is the receiving side, for tests and other relays.
;;;;
;;;; The socket is cl-transport/sockets' (portable across SBCL and modus), so this
;;;; file has no socket code of its own.

(in-package #:cl-nostr.udp)

(defconstant +max-datagram+ 1472
  "Ethernet's 1500 less the IPv4 and UDP headers: the largest datagram that crosses
the path unfragmented.")

(define-condition datagram-too-large (error)
  ((size :initarg :size :reader datagram-size))
  (:report (lambda (c s)
             (format s "event is ~d bytes; a UDP datagram carries at most ~d unfragmented"
                     (datagram-size c) +max-datagram+))))

(defun event->datagram (event)
  "The octets to send for EVENT: its JSON, UTF-8 encoded.  Signals DATAGRAM-TOO-LARGE
rather than return bytes the path would fragment (and a relay would drop)."
  (let ((octets (u:string->utf8 (ev:event->json event))))
    (when (> (length octets) +max-datagram+)
      (error 'datagram-too-large :size (length octets)))
    octets))

(defun %send-datagram (host port octets)
  (let ((ep (cl-transport.sockets:udp-open :host "0.0.0.0")))   ; the wildcard: loopback cannot send off-host
    (unwind-protect
         (unless (eq :ok (cl-transport.sockets:udp-send ep host port octets))
           (error "could not send a datagram to ~a:~d" host port))
      (cl-transport.sockets:udp-close ep))))

(defun publish-datagram (host port event)
  "Send EVENT to HOST:PORT as one datagram and return its id.  Nothing is read back:
the relay answers no datagram, so this proves only that the bytes were handed to the
network.  HOST is a dotted quad or a name.  The event is in the clear; see
PUBLISH-DATAGRAM-ENCRYPTED."
  (%send-datagram host port (event->datagram event))
  (ev:event-id event))

(defun encrypt-datagram (ephemeral event relay-pubkey-hex)
  "EVENT sealed to RELAY-PUBKEY-HEX as one datagram: the ephemeral keypair's x-only
pubkey (32 bytes), then the NIP-44 v2 payload of the event's JSON, under the conversation
key between the ephemeral secret and the relay.  EPHEMERAL is used as given; see
ENCRYPTED-DATAGRAM, which makes a fresh one.  Signals DATAGRAM-TOO-LARGE past the bound."
  (let* ((payload (gossamer:with-fixed-scratch ((conversation :octets 32))
                    (nip44::%conversation-key-into ephemeral (u:hex->bytes relay-pubkey-hex) conversation)
                    (nip44:nip44-encrypt-octets-with-nonce
                     (u:string->utf8 (ev:event->json event)) conversation (u:random-bytes 32))))
         (octets (concatenate '(simple-array (unsigned-byte 8) (*))
                              (u:hex->bytes (k:public-hex ephemeral)) payload)))
    (when (> (length octets) +max-datagram+)
      (error 'datagram-too-large :size (length octets)))
    octets))

(defun encrypted-datagram (event relay-pubkey-hex)
  "ENCRYPT-DATAGRAM under a fresh ephemeral key.  The key's pubkey must not begin with
'{' (0x7b): the relay tries plaintext JSON first, and an encrypted datagram opening with
that byte would be taken for one.  The relay copes either way; the rule is applied here
as well, so a sender never produces the ambiguous case."
  (loop (let* ((ephemeral (k:generate-keypair))
               (octets (unwind-protect (encrypt-datagram ephemeral event relay-pubkey-hex)
                         (k:keypair-wipe ephemeral))))
          (unless (= (aref octets 0) #x7b) (return octets)))))

(defun publish-datagram-encrypted (host port event relay-pubkey-hex)
  "PUBLISH-DATAGRAM, NIP-44 encrypted to the relay's public key: a passive observer sees
an ephemeral key and random bytes, not the event.  Returns the event id."
  (%send-datagram host port (encrypted-datagram event relay-pubkey-hex))
  (ev:event-id event))

(defun open-datagram (relay-keypair datagram)
  "The plaintext octets of an encrypted DATAGRAM, opened with the relay's keypair.  The
receiving side of ENCRYPTED-DATAGRAM.  Signals on any framing, key or MAC failure."
  (gossamer:with-fixed-scratch ((conversation :octets 32))
    (nip44::%conversation-key-into relay-keypair (subseq datagram 0 32) conversation)
    (nip44:nip44-decrypt-octets conversation (subseq datagram 32))))

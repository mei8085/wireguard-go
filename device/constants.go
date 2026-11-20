/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"time"
)

/* Specification constants */

const (
	RekeyAfterMessages      = (1 << 60)
	RejectAfterMessages     = (1 << 64) - (1 << 13) - 1
	RekeyAfterTime          = time.Second * 120
	RekeyAttemptTime        = time.Second * 90
	RekeyTimeout            = time.Second * 5
	MaxTimerHandshakes      = 90 / 5 /* RekeyAttemptTime / RekeyTimeout */
	RekeyTimeoutJitterMaxMs = 334
	RejectAfterTime         = time.Second * 180
	KeepaliveTimeout        = time.Second * 10
	CookieRefreshTime       = time.Second * 120
	HandshakeInitationRate  = time.Second / 50
	PaddingMultiple         = 16
)

const (
	MinMessageSize = MessageKeepaliveSize                  // minimum size of transport message (keepalive)
	MaxMessageSize = MaxSegmentSize                        // maximum size of transport message
	MaxContentSize = MaxSegmentSize - MessageTransportSize // maximum size of transport message content
)

/* Implementation constants */

const (
	UnderLoadAfterTime = time.Second // how long does the device remain under load after detected
	MaxPeers           = 1 << 16     // maximum number of configured peers
)

/* Cookie reply retry constants
 *
 * When a valid cookie reply is received, the handshake is retried
 * promptly instead of waiting for the retransmit timer, so that
 * legitimate peers recover quickly while the responder is under load.
 * Since a cookie reply only proves that its sender observed our last
 * MAC1 (the reply encryption key is derived from the responder's public
 * key), an on-path attacker can forge replies to prod us into sending
 * handshake initiations. The exponential backoff and the retry cap
 * below bound that amplification to a small, fixed number of extra
 * initiations per handshake episode.
 */

const (
	CookieRetryBackoffMin = time.Millisecond * 50 // initial backoff between cookie-triggered handshake retries
	CookieRetryBackoffMax = RekeyTimeout          // maximum backoff between cookie-triggered handshake retries
	MaxCookieRetries      = 16                    // maximum cookie-triggered retries per handshake episode
)

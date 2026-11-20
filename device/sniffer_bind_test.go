/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"encoding/binary"
	"sync"

	"golang.zx2c4.com/wireguard/conn"
)

// snifferBind wraps a conn.Bind and copies every transmitted handshake
// initiation into a channel, without otherwise altering packet delivery.
// It exists solely for anti-replay tests.
type snifferBind struct {
	conn.Bind
	mu          sync.Mutex
	initiations chan []byte
}

func newSnifferBind(inner conn.Bind) *snifferBind {
	return &snifferBind{
		Bind:        inner,
		initiations: make(chan []byte, 32),
	}
}

func (s *snifferBind) Send(bufs [][]byte, ep conn.Endpoint) error {
	for _, b := range bufs {
		if len(b) >= 4 && binary.LittleEndian.Uint32(b[:4]) == MessageInitiationType {
			s.mu.Lock()
			select {
			case s.initiations <- append([]byte(nil), b...):
			default:
			}
			s.mu.Unlock()
		}
	}
	return s.Bind.Send(bufs, ep)
}

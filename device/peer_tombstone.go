/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"time"

	"golang.zx2c4.com/wireguard/tai64n"
)

// handshakeAntiReplayState is the security-critical anti-replay state that
// must outlive any single Peer instance.
//
// A peer identified by its static public key can be removed and re-created
// during a configuration reload (for example via an IPC "replace_peers"
// operation). If this state were discarded together with the old Peer, a
// replayed handshake initiation captured before the reload would be accepted
// by the freshly created peer, whose lastTimestamp is the zero value. An
// attacker could use this to force a new handshake response and hijack the
// peer's endpoint through roaming, or to flood the peer with replayed
// initiations. The state is therefore kept on the Device in a tombstone map,
// keyed by the peer's static public key.
type handshakeAntiReplayState struct {
	// lastTimestamp is the greatest TAI64N timestamp observed in an
	// accepted handshake initiation from this peer.
	lastTimestamp tai64n.Timestamp
	// lastInitiationConsumption is the wall-clock time at which the most
	// recent handshake initiation from this peer was consumed. It backs
	// the HandshakeInitationRate flood protection.
	lastInitiationConsumption time.Time
	// retiredAt is when the owning peer was removed. It is used to expire
	// tombstone entries that are never claimed by a re-created peer.
	retiredAt time.Time
}

// peerAntiReplayTombstoneTTL bounds how long anti-replay state is retained
// for a peer that has been removed without being re-created. RejectAfterTime
// (180s) is the lifetime of WireGuard key material; any initiation older than
// the retained timestamp is rejected regardless, so an entry older than this
// TTL can no longer add protection.
const peerAntiReplayTombstoneTTL = RejectAfterTime

// retirePeerAntiReplayState snapshots the anti-replay state of a peer that is
// being removed, so that a later peer created with the same static public key
// can inherit it. Callers must hold device.peers.Lock().
func (device *Device) retirePeerAntiReplayState(peer *Peer) {
	handshake := &peer.handshake
	handshake.mutex.RLock()
	state := handshakeAntiReplayState{
		lastTimestamp:             handshake.lastTimestamp,
		lastInitiationConsumption: handshake.lastInitiationConsumption,
		retiredAt:                 time.Now(),
	}
	handshake.mutex.RUnlock()

	// A zero timestamp means no initiation was ever consumed; retaining such
	// an entry provides no anti-replay benefit.
	var zeroTimestamp tai64n.Timestamp
	if state.lastTimestamp == zeroTimestamp && state.lastInitiationConsumption.IsZero() {
		return
	}

	device.peerTombstonesMu.Lock()
	defer device.peerTombstonesMu.Unlock()
	device.prunePeerTombstonesLocked(time.Now())
	device.peerTombstones[handshake.remoteStatic] = state
}

// claimPeerAntiReplayState transfers any retained anti-replay state for the
// given static public key to the newly created peer. The returned state is
// removed from the tombstone map. Callers must hold device.peers.Lock().
func (device *Device) claimPeerAntiReplayState(publicKey NoisePublicKey) (state handshakeAntiReplayState, ok bool) {
	device.peerTombstonesMu.Lock()
	defer device.peerTombstonesMu.Unlock()
	device.prunePeerTombstonesLocked(time.Now())
	state, ok = device.peerTombstones[publicKey]
	if ok {
		delete(device.peerTombstones, publicKey)
	}
	return state, ok
}

// prunePeerTombstonesLocked drops tombstone entries whose TTL has elapsed.
// Callers must hold device.peerTombstonesMu.
func (device *Device) prunePeerTombstonesLocked(now time.Time) {
	for key, state := range device.peerTombstones {
		if now.Sub(state.retiredAt) > peerAntiReplayTombstoneTTL {
			delete(device.peerTombstones, key)
		}
	}
}

// clearPeerAntiReplayTombstones removes all retained anti-replay state. It is
// called when the device is closed, when no peers can be created afterwards.
func (device *Device) clearPeerAntiReplayTombstones() {
	device.peerTombstonesMu.Lock()
	defer device.peerTombstonesMu.Unlock()
	device.peerTombstones = make(map[NoisePublicKey]handshakeAntiReplayState)
}

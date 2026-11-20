/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/tai64n"
)

// TestPeerTombstoneInheritance verifies that the handshake anti-replay state
// of a removed peer is inherited by a replacement peer carrying the same
// static public key.
func TestPeerTombstoneInheritance(t *testing.T) {
	dev := randDevice(t)
	defer dev.Close()

	pub, err := newPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	remoteStatic := pub.publicKey()

	peer, err := dev.NewPeer(remoteStatic)
	if err != nil {
		t.Fatal(err)
	}

	// Simulate the state left behind after processing a real initiation.
	wantTimestamp := tai64n.Now()
	wantConsumption := time.Now()
	peer.handshake.mutex.Lock()
	peer.handshake.lastTimestamp = wantTimestamp
	peer.handshake.lastInitiationConsumption = wantConsumption
	peer.handshake.mutex.Unlock()

	// Removing the peer must snapshot its anti-replay state.
	dev.peers.Lock()
	removePeerLocked(dev, peer, remoteStatic)
	dev.peers.Unlock()

	dev.peerTombstonesMu.Lock()
	stored, ok := dev.peerTombstones[remoteStatic]
	dev.peerTombstonesMu.Unlock()
	if !ok {
		t.Fatal("expected anti-replay state to be retained after peer removal")
	}
	if stored.lastTimestamp != wantTimestamp {
		t.Error("tombstone did not retain lastTimestamp")
	}
	if !stored.lastInitiationConsumption.Equal(wantConsumption) {
		t.Error("tombstone did not retain lastInitiationConsumption")
	}
	if stored.retiredAt.IsZero() {
		t.Error("tombstone did not record retirement time")
	}

	// A newly created peer with the same public key must claim the state,
	// and the tombstone entry must be consumed.
	replacement, err := dev.NewPeer(remoteStatic)
	if err != nil {
		t.Fatal(err)
	}
	replacement.handshake.mutex.RLock()
	gotTimestamp := replacement.handshake.lastTimestamp
	gotConsumption := replacement.handshake.lastInitiationConsumption
	replacement.handshake.mutex.RUnlock()
	if gotTimestamp != wantTimestamp {
		t.Error("replacement peer did not inherit lastTimestamp")
	}
	if !gotConsumption.Equal(wantConsumption) {
		t.Error("replacement peer did not inherit lastInitiationConsumption")
	}

	dev.peerTombstonesMu.Lock()
	_, ok = dev.peerTombstones[remoteStatic]
	dev.peerTombstonesMu.Unlock()
	if ok {
		t.Error("tombstone entry was not removed after being claimed")
	}
}

// TestPeerTombstoneSkipsUntouchedPeer verifies that removing a peer that
// never processed an initiation does not leave a tombstone behind.
func TestPeerTombstoneSkipsUntouchedPeer(t *testing.T) {
	dev := randDevice(t)
	defer dev.Close()

	pub, err := newPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	remoteStatic := pub.publicKey()

	peer, err := dev.NewPeer(remoteStatic)
	if err != nil {
		t.Fatal(err)
	}

	dev.peers.Lock()
	removePeerLocked(dev, peer, remoteStatic)
	dev.peers.Unlock()

	dev.peerTombstonesMu.Lock()
	_, ok := dev.peerTombstones[remoteStatic]
	dev.peerTombstonesMu.Unlock()
	if ok {
		t.Error("no tombstone expected for a peer whose handshake was never consumed")
	}
}

// TestPeerTombstoneExpiry verifies that entries past their TTL are pruned.
func TestPeerTombstoneExpiry(t *testing.T) {
	dev := randDevice(t)
	defer dev.Close()

	pub, err := newPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	remoteStatic := pub.publicKey()

	peer, err := dev.NewPeer(remoteStatic)
	if err != nil {
		t.Fatal(err)
	}
	peer.handshake.mutex.Lock()
	peer.handshake.lastTimestamp = tai64n.Now()
	peer.handshake.lastInitiationConsumption = time.Now()
	peer.handshake.mutex.Unlock()

	dev.peers.Lock()
	removePeerLocked(dev, peer, remoteStatic)
	dev.peers.Unlock()

	// Age the entry beyond its TTL.
	dev.peerTombstonesMu.Lock()
	entry := dev.peerTombstones[remoteStatic]
	entry.retiredAt = time.Now().Add(-peerAntiReplayTombstoneTTL - time.Second)
	dev.peerTombstones[remoteStatic] = entry
	dev.peerTombstonesMu.Unlock()

	// Claiming another (unrelated) peer runs the lazy prune.
	other, err := newPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := dev.NewPeer(other.publicKey()); err != nil {
		t.Fatal(err)
	}

	dev.peerTombstonesMu.Lock()
	_, ok := dev.peerTombstones[remoteStatic]
	dev.peerTombstonesMu.Unlock()
	if ok {
		t.Error("expected expired tombstone entry to be pruned")
	}
}

// TestPeerTombstoneClearOnClose verifies that closing the device drops all
// retained anti-replay state.
func TestPeerTombstoneClearOnClose(t *testing.T) {
	dev := randDevice(t)

	pub, err := newPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	remoteStatic := pub.publicKey()

	peer, err := dev.NewPeer(remoteStatic)
	if err != nil {
		t.Fatal(err)
	}
	peer.handshake.mutex.Lock()
	peer.handshake.lastTimestamp = tai64n.Now()
	peer.handshake.lastInitiationConsumption = time.Now()
	peer.handshake.mutex.Unlock()

	dev.peers.Lock()
	removePeerLocked(dev, peer, remoteStatic)
	dev.peers.Unlock()

	dev.Close()

	dev.peerTombstonesMu.Lock()
	n := len(dev.peerTombstones)
	dev.peerTombstonesMu.Unlock()
	if n != 0 {
		t.Errorf("expected no tombstone entries after Close, got %d", n)
	}
}

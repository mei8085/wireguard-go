/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"encoding/binary"
	"encoding/hex"
	"testing"
	"time"
)

// rotatePeerPresharedKey rotates the preshared key of every peer on dev
// to psk via the UAPI, exercising the same path as a configuration update.
func rotatePeerPresharedKey(t *testing.T, dev *Device, psk NoisePresharedKey) {
	t.Helper()
	dev.peers.RLock()
	defer dev.peers.RUnlock()
	for pk := range dev.peers.keyMap {
		cfg := uapiCfg(
			"public_key", hex.EncodeToString(pk[:]),
			"preshared_key", hex.EncodeToString(psk[:]),
		)
		if err := dev.IpcSet(cfg); err != nil {
			t.Fatalf("failed to rotate preshared key: %v", err)
		}
	}
}

// handshakePeers creates a started pair of peers connecting dev1 and dev2.
func handshakePeers(t *testing.T, dev1, dev2 *Device) (peerOn1, peerOn2 *Peer) {
	t.Helper()
	peerOn2, err := dev1.NewPeer(dev2.staticIdentity.privateKey.publicKey())
	if err != nil {
		t.Fatal(err)
	}
	peerOn1, err = dev2.NewPeer(dev1.staticIdentity.privateKey.publicKey())
	if err != nil {
		t.Fatal(err)
	}
	peerOn1.Start()
	peerOn2.Start()
	return peerOn1, peerOn2
}

// exchangeHandshake runs a full handshake between peerOn2 (initiator, on
// dev1) and peerOn1 (responder, on dev2), deriving keypairs on both sides.
func exchangeHandshake(t *testing.T, dev1, dev2 *Device, peerOn1, peerOn2 *Peer) {
	t.Helper()

	msg1, err := dev1.CreateMessageInitiation(peerOn2)
	assertNil(t, err)
	if peer := dev2.ConsumeMessageInitiation(msg1); peer == nil {
		t.Fatal("handshake failed at initiation message")
	}

	msg2, err := dev2.CreateMessageResponse(peerOn1)
	assertNil(t, err)
	if peer := dev1.ConsumeMessageResponse(msg2); peer == nil {
		t.Fatal("handshake failed at response message")
	}

	assertNil(t, peerOn1.BeginSymmetricSession())
	assertNil(t, peerOn2.BeginSymmetricSession())
}

func TestPresharedKeyRotationRetiresKeypairs(t *testing.T) {
	dev1 := randDevice(t)
	dev2 := randDevice(t)
	defer dev1.Close()
	defer dev2.Close()

	peerOn1, peerOn2 := handshakePeers(t, dev1, dev2)
	exchangeHandshake(t, dev1, dev2, peerOn1, peerOn2)

	if peerOn2.keypairs.current == nil {
		t.Fatal("expected an established current keypair before rotation")
	}
	oldIndex := peerOn2.keypairs.current.localIndex
	oldKeypair := peerOn2.keypairs.current

	// Rotate the preshared key on dev1's peer.
	var psk NoisePresharedKey
	psk[0] = 1
	peerOn2.UpdatePresharedKey(psk)

	if gen := peerOn2.keyGeneration.Load(); gen != 1 {
		t.Fatalf("expected key generation 1 after rotation, got %d", gen)
	}

	// All keypairs from the retired generation must be gone.
	if peerOn2.keypairs.current != nil || peerOn2.keypairs.previous != nil || peerOn2.keypairs.next.Load() != nil {
		t.Fatal("expected all old-generation keypairs to be retired")
	}

	// The retired keypair must reject further sends...
	if nonce := oldKeypair.sendNonce.Load(); nonce != RejectAfterMessages {
		t.Fatalf("expected retired keypair send nonce %d, got %d", uint64(RejectAfterMessages), nonce)
	}

	// ...and its index must be removed, so incoming packets referencing
	// the old session are rejected before they can update state.
	if entry := dev1.indexTable.Lookup(oldIndex); entry.keypair != nil || entry.handshake != nil {
		t.Fatal("expected retired keypair to be removed from the index table")
	}

	// Rotating to the same key again must not advance the generation.
	peerOn2.UpdatePresharedKey(psk)
	if gen := peerOn2.keyGeneration.Load(); gen != 1 {
		t.Fatalf("expected unchanged key generation, got %d", gen)
	}
}

func TestPresharedKeyRotationNewSessionUsesNewGeneration(t *testing.T) {
	dev1 := randDevice(t)
	dev2 := randDevice(t)
	defer dev1.Close()
	defer dev2.Close()

	peerOn1, peerOn2 := handshakePeers(t, dev1, dev2)
	exchangeHandshake(t, dev1, dev2, peerOn1, peerOn2)

	// Rotate both sides to the same new preshared key.
	var psk NoisePresharedKey
	psk[0] = 2
	peerOn1.UpdatePresharedKey(psk)
	peerOn2.UpdatePresharedKey(psk)

	// A new handshake must succeed and produce keypairs tagged with the
	// new generation.
	exchangeHandshake(t, dev1, dev2, peerOn1, peerOn2)

	if gen := peerOn2.keypairs.current.keyGeneration; gen != 1 {
		t.Fatalf("initiator keypair has generation %d, want 1", gen)
	}
	next := peerOn1.keypairs.next.Load()
	if next == nil {
		t.Fatal("responder has no next keypair after handshake")
	}
	if gen := next.keyGeneration; gen != 1 {
		t.Fatalf("responder keypair has generation %d, want 1", gen)
	}

	// The new keypairs must be usable in both directions.
	testMsg := []byte("wireguard psk rotation test")
	var nonce [12]byte
	out := peerOn2.keypairs.current.send.Seal(nil, nonce[:], testMsg, nil)
	opened, err := next.receive.Open(nil, nonce[:], out, nil)
	assertNil(t, err)
	assertEqual(t, opened, testMsg)
}

func TestPresharedKeyRotationAbortsInProgressHandshake(t *testing.T) {
	dev1 := randDevice(t)
	dev2 := randDevice(t)
	defer dev1.Close()
	defer dev2.Close()

	peerOn1, peerOn2 := handshakePeers(t, dev1, dev2)

	// The initiator starts a handshake, the responder consumes it, and
	// then the preshared key is rotated before the handshake completes.
	msg1, err := dev1.CreateMessageInitiation(peerOn2)
	assertNil(t, err)
	if peer := dev2.ConsumeMessageInitiation(msg1); peer == nil {
		t.Fatal("handshake failed at initiation message")
	}

	var psk NoisePresharedKey
	psk[0] = 3
	peerOn1.UpdatePresharedKey(psk)

	// The responder's in-progress handshake was aborted: creating a
	// response must fail...
	if _, err := dev2.CreateMessageResponse(peerOn1); err == nil {
		t.Fatal("expected CreateMessageResponse to fail after rotation")
	}

	// ...and deriving a session from it must fail as well.
	if err := peerOn1.BeginSymmetricSession(); err == nil {
		t.Fatal("expected BeginSymmetricSession to fail after rotation")
	}
}

func TestPresharedKeyRotationRejectsStaleResponse(t *testing.T) {
	dev1 := randDevice(t)
	dev2 := randDevice(t)
	defer dev1.Close()
	defer dev2.Close()

	peerOn1, peerOn2 := handshakePeers(t, dev1, dev2)

	// Complete the message exchange, but rotate the initiator's
	// preshared key before it consumes the (possibly retried) response.
	msg1, err := dev1.CreateMessageInitiation(peerOn2)
	assertNil(t, err)
	if peer := dev2.ConsumeMessageInitiation(msg1); peer == nil {
		t.Fatal("handshake failed at initiation message")
	}
	msg2, err := dev2.CreateMessageResponse(peerOn1)
	assertNil(t, err)

	var psk NoisePresharedKey
	psk[0] = 4
	peerOn2.UpdatePresharedKey(psk)

	// The stale response must be rejected consistently.
	if peer := dev1.ConsumeMessageResponse(msg2); peer != nil {
		t.Fatal("expected stale response to be rejected after rotation")
	}
	if err := peerOn2.BeginSymmetricSession(); err == nil {
		t.Fatal("expected BeginSymmetricSession to fail after rotation")
	}
	if peerOn2.keypairs.current != nil {
		t.Fatal("no session may be established from a retired generation")
	}
}

func TestPresharedKeyRotationEndToEnd(t *testing.T) {
	goroutineLeakCheck(t)
	pair := genTestPair(t, false)
	done := make(chan struct{})
	defer close(done)

	// Establish a session.
	pair.Send(t, Ping, done)
	pair.Send(t, Pong, done)

	// Capture the old session indexes on both devices.
	oldIndexes := make([][]uint32, 2)
	for i := range pair {
		for _, peer := range pair[i].dev.peers.keyMap {
			peer.keypairs.RLock()
			if peer.keypairs.current != nil {
				oldIndexes[i] = append(oldIndexes[i], peer.keypairs.current.localIndex)
			}
			peer.keypairs.RUnlock()
		}
	}
	if len(oldIndexes[0]) == 0 || len(oldIndexes[1]) == 0 {
		t.Fatal("expected established sessions before rotation")
	}

	// Rotate the preshared key on both devices.
	var psk NoisePresharedKey
	for i := range psk {
		psk[i] = byte(i + 1)
	}
	rotatePeerPresharedKey(t, pair[0].dev, psk)
	rotatePeerPresharedKey(t, pair[1].dev, psk)

	// Old session indexes must be retired on both devices.
	for i := range pair {
		for _, index := range oldIndexes[i] {
			if entry := pair[i].dev.indexTable.Lookup(index); entry.keypair != nil || entry.handshake != nil {
				t.Errorf("device %d: old session index %d still present after rotation", i, index)
			}
		}
	}

	// Traffic must flow again, now over a session derived from the new
	// preshared key generation.
	pair.Send(t, Ping, done)
	pair.Send(t, Pong, done)

	deadline := time.Now().Add(5 * time.Second)
	for i := range pair {
		for _, peer := range pair[i].dev.peers.keyMap {
			for {
				peer.keypairs.RLock()
				current := peer.keypairs.current
				peer.keypairs.RUnlock()
				if current != nil && current.keyGeneration == 1 {
					break
				}
				if time.Now().After(deadline) {
					t.Fatalf("device %d: no current keypair from generation 1", i)
				}
				time.Sleep(10 * time.Millisecond)
			}
		}
	}
}

// TestPresharedKeyRotationConcurrentHandshake runs handshakes concurrently
// with preshared key rotation, exercising the generation checks under the
// race detector. Every handshake must either complete entirely within one
// generation or be rejected; it must never install a keypair from a
// retired generation.
func TestPresharedKeyRotationConcurrentHandshake(t *testing.T) {
	dev1 := randDevice(t)
	dev2 := randDevice(t)
	defer dev1.Close()
	defer dev2.Close()

	peerOn1, peerOn2 := handshakePeers(t, dev1, dev2)

	done := make(chan struct{})
	exited := make(chan struct{})
	go func() {
		defer close(exited)
		for i := 0; ; i++ {
			select {
			case <-done:
				return
			default:
			}
			var psk NoisePresharedKey
			binary.LittleEndian.PutUint64(psk[:8], uint64(i))
			peerOn1.UpdatePresharedKey(psk)
			peerOn2.UpdatePresharedKey(psk)
		}
	}()

	for i := 0; i < 200; i++ {
		msg1, err := dev1.CreateMessageInitiation(peerOn2)
		if err != nil {
			continue
		}
		if dev2.ConsumeMessageInitiation(msg1) == nil {
			continue
		}
		msg2, err := dev2.CreateMessageResponse(peerOn1)
		if err != nil {
			continue
		}
		if dev1.ConsumeMessageResponse(msg2) == nil {
			continue
		}
		if err := peerOn1.BeginSymmetricSession(); err != nil {
			continue
		}
		if err := peerOn2.BeginSymmetricSession(); err != nil {
			continue
		}
		// A successfully derived keypair must belong to the peer's
		// current generation.
		if kp := peerOn2.keypairs.Current(); kp != nil && kp.keyGeneration != peerOn2.keyGeneration.Load() {
			t.Fatalf("installed keypair from retired generation %d (current %d)",
				kp.keyGeneration, peerOn2.keyGeneration.Load())
		}
	}
	close(done)
	<-exited

	// After rotation stops, a final handshake must succeed.
	var psk NoisePresharedKey
	psk[0] = 0xff
	peerOn1.UpdatePresharedKey(psk)
	peerOn2.UpdatePresharedKey(psk)
	exchangeHandshake(t, dev1, dev2, peerOn1, peerOn2)
	if kp := peerOn2.keypairs.Current(); kp == nil {
		t.Fatal("expected a current keypair after final handshake")
	}
}

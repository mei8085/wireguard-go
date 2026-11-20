/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/conn/bindtest"
	"golang.zx2c4.com/wireguard/tai64n"
	"golang.zx2c4.com/wireguard/tun/tuntest"
)

var errCaptureTimeout = errors.New("timed out waiting for handshake initiation")

// recordedLogger is a Logger that captures verbose log lines for later
// inspection while remaining safe for concurrent use.
type recordedLogger struct {
	mu   sync.Mutex
	logs []string
}

func newRecordedLogger() (*Logger, *recordedLogger) {
	rec := &recordedLogger{}
	logger := &Logger{
		Verbosef: func(format string, args ...any) {
			rec.mu.Lock()
			rec.logs = append(rec.logs, fmt.Sprintf(format, args...))
			rec.mu.Unlock()
		},
		Errorf: DiscardLogf,
	}
	return logger, rec
}

func (r *recordedLogger) contains(substr string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, line := range r.logs {
		if strings.Contains(line, substr) {
			return true
		}
	}
	return false
}

func (r *recordedLogger) reset() {
	r.mu.Lock()
	r.logs = r.logs[:0]
	r.mu.Unlock()
}

// reloadResponderPeer destroys and re-creates the given peer on dev through
// the same IPC replace_peers path used by a real configuration reload.
func reloadResponderPeer(t *testing.T, dev *Device, peerPub NoisePublicKey) *Peer {
	t.Helper()
	reloadCfg := uapiCfg(
		"replace_peers", "true",
		"public_key", hex.EncodeToString(peerPub[:]),
		"protocol_version", "1",
		"replace_allowed_ips", "true",
		"allowed_ip", "1.0.0.1/32",
	)
	if err := dev.IpcSet(reloadCfg); err != nil {
		t.Fatalf("reload failed: %v", err)
	}
	peer := dev.LookupPeer(peerPub)
	if peer == nil {
		t.Fatal("peer missing after reload")
	}
	return peer
}

func peerConsumedTimestamp(t *testing.T, peer *Peer) tai64n.Timestamp {
	t.Helper()
	peer.handshake.mutex.RLock()
	ts := peer.handshake.lastTimestamp
	peer.handshake.mutex.RUnlock()
	return ts
}

func waitForConsumedInitiation(t *testing.T, peer *Peer, timeout time.Duration) tai64n.Timestamp {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		peer.handshake.mutex.RLock()
		ts := peer.handshake.lastTimestamp
		peer.handshake.mutex.RUnlock()
		if ts != (tai64n.Timestamp{}) {
			return ts
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatal("peer did not consume a handshake initiation in time")
	return tai64n.Timestamp{}
}

// waitForTimestampAdvance blocks until the peer's lastTimestamp is strictly
// newer than previous, or fails the test on timeout.
func waitForTimestampAdvance(t *testing.T, peer *Peer, previous tai64n.Timestamp, timeout time.Duration) tai64n.Timestamp {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		peer.handshake.mutex.RLock()
		ts := peer.handshake.lastTimestamp
		peer.handshake.mutex.RUnlock()
		if ts.After(previous) {
			return ts
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("anti-replay timestamp did not advance past %v", previous)
	return tai64n.Timestamp{}
}

// waitForEndpoint blocks until the peer has learned an endpoint, or fails.
func waitForEndpoint(t *testing.T, peer *Peer, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		peer.endpoint.Lock()
		ep := peer.endpoint.val
		peer.endpoint.Unlock()
		if ep != nil {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatal("peer endpoint was never set")
}

// replayTestPair builds two devices on channel binds with dev0 as initiator
// and dev1 as responder. sniffer wraps dev0's bind so its outgoing handshake
// initiations can be captured without disturbing normal delivery.
func replayTestPair(t *testing.T) (pair [2]*Device, binds [2]conn.Bind, sniffer *snifferBind, recs [2]*recordedLogger) {
	cfg, endpointCfg := genConfigs(t)
	channelBinds := bindtest.NewChannelBinds()
	sniffer = newSnifferBind(channelBinds[0])
	binds[0] = sniffer
	binds[1] = channelBinds[1]
	var tuns [2]*tuntest.ChannelTUN
	for i := range pair {
		tuns[i] = tuntest.NewChannelTUN()
		logger, rec := newRecordedLogger()
		recs[i] = rec
		pair[i] = NewDevice(tuns[i].TUN(), binds[i], logger)
		if err := pair[i].IpcSet(cfg[i]); err != nil {
			t.Fatalf("configure device %d: %v", i, err)
		}
		if err := pair[i].Up(); err != nil {
			t.Fatalf("up device %d: %v", i, err)
		}
		t.Cleanup(pair[i].Close)
	}
	if err := pair[0].IpcSet(fmt.Sprintf(endpointCfg[0], 1)); err != nil {
		t.Fatal(err)
	}
	return pair, binds, sniffer, recs
}

func awaitInitiation(t *testing.T, sniffer *snifferBind) []byte {
	t.Helper()
	deadline := time.After(2 * time.Second)
	for {
		select {
		case pkt := <-sniffer.initiations:
			return pkt
		case <-deadline:
			t.Fatal(errCaptureTimeout)
		}
	}
}

// sendInitiationAndCapture drives SendHandshakeInitiation until the local
// RekeyTimeout throttle permits a new initiation and it is observed.
func sendInitiationAndCapture(t *testing.T, peer *Peer, sniffer *snifferBind) []byte {
	t.Helper()
	deadline := time.Now().Add(RekeyTimeout + 2*time.Second)
	for time.Now().Before(deadline) {
		if err := peer.SendHandshakeInitiation(false); err != nil {
			t.Fatal(err)
		}
		select {
		case pkt := <-sniffer.initiations:
			return pkt
		case <-time.After(50 * time.Millisecond):
		}
	}
	t.Fatal("no new handshake initiation was transmitted")
	return nil
}

// injectOnResponder feeds a raw packet into the responder's receive channel,
// impersonating a packet arriving from the network.
func injectOnResponder(bind conn.Bind, pkt []byte) {
	*bind.(*bindtest.ChannelBind).Rx4() <- append([]byte(nil), pkt...)
}

// TestReplayAfterPeerReload verifies that a handshake initiation captured
// before an IPC replace_peers reload cannot be replayed against the
// re-created peer afterwards, while a fresh initiation still succeeds and
// legitimate endpoint roaming continues to work.
func TestReplayAfterPeerReload(t *testing.T) {
	pair, binds, sniffer, recs := replayTestPair(t)
	initiatorPeer := pair[0].LookupPeer(pair[1].staticIdentity.publicKey)
	responderPeer := pair[1].LookupPeer(pair[0].staticIdentity.publicKey)

	// Phase 1: complete a genuine handshake and capture the initiation.
	if err := initiatorPeer.SendHandshakeInitiation(false); err != nil {
		t.Fatal(err)
	}
	captured := awaitInitiation(t, sniffer)

	consumedTimestamp := waitForConsumedInitiation(t, responderPeer, 2*time.Second)

	// Phase 2: reload the responder with replace_peers, rebuilding the peer.
	newPeer := reloadResponderPeer(t, pair[1], pair[0].staticIdentity.publicKey)
	if newPeer == responderPeer {
		t.Fatal("expected a freshly created peer object after reload")
	}

	// The replacement peer must inherit the anti-replay timestamp.
	if got := peerConsumedTimestamp(t, newPeer); got != consumedTimestamp {
		t.Fatalf("reloaded peer lost anti-replay timestamp: want %v, got %v", consumedTimestamp, got)
	}

	// Phase 3: replay the captured pre-reload initiation. It must be rejected
	// without advancing any handshake state or touching the endpoint.
	recs[1].reset()
	injectOnResponder(binds[1], captured)
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) && !recs[1].contains("handshake replay") {
		time.Sleep(2 * time.Millisecond)
	}
	if !recs[1].contains("handshake replay") {
		t.Error("replayed pre-reload initiation was not rejected")
	}
	newPeer.handshake.mutex.RLock()
	stateAfterReplay := newPeer.handshake.state
	tsAfterReplay := newPeer.handshake.lastTimestamp
	newPeer.handshake.mutex.RUnlock()
	if stateAfterReplay != handshakeZeroed {
		t.Errorf("replayed initiation advanced handshake state to %v", stateAfterReplay)
	}
	if tsAfterReplay != consumedTimestamp {
		t.Error("replayed initiation modified the retained timestamp")
	}
	newPeer.endpoint.Lock()
	endpointAfterReplay := newPeer.endpoint.val
	newPeer.endpoint.Unlock()
	if endpointAfterReplay != nil {
		t.Error("replayed initiation hijacked the reloaded peer's endpoint")
	}

	// Phase 4: a legitimate fresh initiation (with a newer timestamp) must
	// still be accepted after the reload, proving that roaming and normal
	// handshakes are not broken.
	_ = sendInitiationAndCapture(t, initiatorPeer, sniffer)
	waitForTimestampAdvance(t, newPeer, consumedTimestamp, 2*time.Second)

	// The accepted packet must have updated (roamed) the endpoint.
	waitForEndpoint(t, newPeer, 2*time.Second)
}

// TestReplayFloodProtectionAcrossReload verifies that the initiation flood
// limiter (lastInitiationConsumption) survives a peer rebuild. The timing
// window involved is only HandshakeInitationRate (20ms), so the inheritance
// itself is checked deterministically here; the end-to-end throttle behavior
// is covered by ConsumeMessageInitiation's existing locking logic.
func TestReplayFloodProtectionAcrossReload(t *testing.T) {
	pair, _, _, _ := replayTestPair(t)
	responderPeer := pair[1].LookupPeer(pair[0].staticIdentity.publicKey)

	// Simulate a recently consumed initiation, as left behind by real traffic.
	wantConsumption := time.Now()
	responderPeer.handshake.mutex.Lock()
	responderPeer.handshake.lastInitiationConsumption = wantConsumption
	responderPeer.handshake.lastTimestamp = tai64n.Now()
	responderPeer.handshake.mutex.Unlock()

	// Rebuild the peer via the real replace_peers path.
	newPeer := reloadResponderPeer(t, pair[1], pair[0].staticIdentity.publicKey)

	newPeer.handshake.mutex.RLock()
	gotConsumption := newPeer.handshake.lastInitiationConsumption
	newPeer.handshake.mutex.RUnlock()
	if !gotConsumption.Equal(wantConsumption) {
		t.Fatalf("reloaded peer lost flood-limiting timestamp: want %v, got %v", wantConsumption, gotConsumption)
	}

	// A flood decision computed against the inherited state must throttle.
	newPeer.handshake.mutex.RLock()
	flood := time.Since(newPeer.handshake.lastInitiationConsumption) <= HandshakeInitationRate
	newPeer.handshake.mutex.RUnlock()
	if !flood {
		t.Error("inherited flood timestamp does not produce a throttle decision")
	}
}

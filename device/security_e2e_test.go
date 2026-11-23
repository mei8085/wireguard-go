/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"encoding/hex"
	"math/rand"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/tun/tuntest"
)

// hubTopology bundles three real Devices connected over loopback UDP:
//
//	hub (10.0.0.1 side)  <-->  spokeA (10.0.1.0/24)
//	                     <-->  spokeB (10.0.2.0/24)
//
// The hub's AllowedIPs cover both spoke ranges, so without isolation it is a
// plain relay. A goroutine simulates the hub's TUN-side router by replaying
// packets written to its TUN back into its TUN, which is what an OS router
// would do after a route lookup.
type hubTopology struct {
	t      *testing.T
	hub    *Device
	spokeA *Device
	spokeB *Device
	tun    struct {
		hub    *tuntest.ChannelTUN
		spokeA *tuntest.ChannelTUN
		spokeB *tuntest.ChannelTUN
	}
	stopRelay chan struct{}
	// hubDelivered is a buffered tee of every plaintext packet the hub
	// writes to its TUN. The relay goroutine owns hub.Inbound itself, so
	// tests observe hub-side delivery through this channel instead.
	hubDelivered chan []byte
}

func genKey(t *testing.T) NoisePrivateKey {
	t.Helper()
	var k NoisePrivateKey
	if _, err := rand.Read(k[:]); err != nil {
		t.Fatalf("rand key: %v", err)
	}
	return k
}

func newHubTopology(t *testing.T) *hubTopology {
	t.Helper()
	topo := &hubTopology{
		t:            t,
		stopRelay:    make(chan struct{}),
		hubDelivered: make(chan []byte, 256),
	}

	hubKey, keyA, keyB := genKey(t), genKey(t), genKey(t)
	pubHub, pubA, pubB := hubKey.publicKey(), keyA.publicKey(), keyB.publicKey()

	topo.tun.hub = tuntest.NewChannelTUN()
	topo.tun.spokeA = tuntest.NewChannelTUN()
	topo.tun.spokeB = tuntest.NewChannelTUN()

	logger := func(name string) *Logger {
		return NewLogger(LogLevelError, name)
	}
	topo.hub = NewDevice(topo.tun.hub.TUN(), conn.NewDefaultBind(), logger("hub"))
	topo.spokeA = NewDevice(topo.tun.spokeA.TUN(), conn.NewDefaultBind(), logger("spokeA"))
	topo.spokeB = NewDevice(topo.tun.spokeB.TUN(), conn.NewDefaultBind(), logger("spokeB"))
	t.Cleanup(func() { close(topo.stopRelay) })
	t.Cleanup(topo.hub.Close)
	t.Cleanup(topo.spokeA.Close)
	t.Cleanup(topo.spokeB.Close)

	// Hub: one peer entry per spoke, each owning its overlay range.
	hubCfg := uapiCfg(
		"private_key", hex.EncodeToString(hubKey[:]),
		"listen_port", "0",
		"replace_peers", "true",
		"public_key", hex.EncodeToString(pubA[:]),
		"protocol_version", "1",
		"replace_allowed_ips", "true",
		"allowed_ip", "10.0.1.0/24",
		"public_key", hex.EncodeToString(pubB[:]),
		"protocol_version", "1",
		"replace_allowed_ips", "true",
		"allowed_ip", "10.0.2.0/24",
	)
	if err := topo.hub.IpcSet(hubCfg); err != nil {
		t.Fatalf("hub config: %v", err)
	}
	if err := topo.hub.Up(); err != nil {
		t.Fatalf("hub up: %v", err)
	}

	configureSpoke := func(dev *Device, key NoisePrivateKey, hubPub NoisePublicKey, ownRange string) {
		cfg := uapiCfg(
			"private_key", hex.EncodeToString(key[:]),
			"listen_port", "0",
			"replace_peers", "true",
			"public_key", hex.EncodeToString(hubPub[:]),
			"protocol_version", "1",
			"replace_allowed_ips", "true",
			// Route the whole overlay through the hub.
			"allowed_ip", "10.0.0.0/16",
		)
		if err := dev.IpcSet(cfg); err != nil {
			t.Fatalf("spoke config: %v", err)
		}
		if err := dev.Up(); err != nil {
			t.Fatalf("spoke up: %v", err)
		}
	}
	configureSpoke(topo.spokeA, keyA, pubHub, "10.0.1.0/24")
	configureSpoke(topo.spokeB, keyB, pubHub, "10.0.2.0/24")

	// Point the spokes at the hub's real listening port.
	hubPort := topo.hub.net.port
	endpointCfg := func(peerPub NoisePublicKey) string {
		return uapiCfg(
			"public_key", hex.EncodeToString(peerPub[:]),
			"endpoint", "127.0.0.1:"+strconv.Itoa(int(hubPort)),
		)
	}
	if err := topo.spokeA.IpcSet(endpointCfg(pubHub)); err != nil {
		t.Fatalf("spokeA endpoint: %v", err)
	}
	if err := topo.spokeB.IpcSet(endpointCfg(pubHub)); err != nil {
		t.Fatalf("spokeB endpoint: %v", err)
	}

	// Simulate the hub TUN router: anything the hub writes to its TUN is
	// re-injected, so a relayed packet re-enters RoutineReadFromTUN and
	// gets re-attributed against the current AllowedIPs/policy. This is
	// the exact path an OS kernel router would take. Every delivered
	// packet is first copied into hubDelivered so tests can assert on
	// hub-side delivery without racing the relay for hub.Inbound.
	go func() {
		for {
			select {
			case <-topo.stopRelay:
				return
			case pkt := <-topo.tun.hub.Inbound:
				cp := append([]byte(nil), pkt...)
				select {
				case topo.hubDelivered <- cp:
				default:
					t.Errorf("hubDelivered tee channel full")
				}
				select {
				case topo.tun.hub.Outbound <- pkt:
				case <-topo.stopRelay:
					return
				}
			}
		}
	}()

	return topo
}

// waitFor asserts that a packet arrives on ch within the timeout.
func waitForPacket(t *testing.T, ch chan []byte, timeout time.Duration, what string) []byte {
	t.Helper()
	select {
	case pkt := <-ch:
		return pkt
	case <-time.After(timeout):
		t.Fatalf("timed out waiting for %s", what)
		return nil
	}
}

// assertNoPacket asserts that nothing arrives on ch within the window.
func assertNoPacket(t *testing.T, ch chan []byte, window time.Duration, what string) {
	t.Helper()
	select {
	case pkt := <-ch:
		t.Fatalf("unexpected packet for %s: %d bytes", what, len(pkt))
	case <-time.After(window):
	}
}

// drainPackets discards every packet already buffered in ch, so a later
// assertNoPacket only observes packets produced after the drain point.
func drainPackets(ch chan []byte) {
	for {
		select {
		case <-ch:
		default:
			return
		}
	}
}

// establishHandshakes forces both spokes through a handshake with the hub.
func (topo *hubTopology) establishHandshakes() {
	pingA := tuntest.Ping(netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("10.0.1.10"))
	topo.tun.spokeA.Outbound <- pingA
	waitForPacket(topo.t, topo.hubDelivered, 5*time.Second, "spokeA->hub handshake ping")
	pingB := tuntest.Ping(netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("10.0.2.10"))
	topo.tun.spokeB.Outbound <- pingB
	waitForPacket(topo.t, topo.hubDelivered, 5*time.Second, "spokeB->hub handshake ping")
}

// TestHubIsolationEndToEnd drives the complete encrypted data path:
// handshakes, normal relay traffic, isolation blocking, live reconfiguration
// and failure-path counter attribution.
func TestHubIsolationEndToEnd(t *testing.T) {
	topo := newHubTopology(t)
	topo.establishHandshakes()

	srcA := netip.MustParseAddr("10.0.1.10")
	srcB := netip.MustParseAddr("10.0.2.10")

	// Phase 1: isolation disabled (default) - peer-to-peer relay works.
	if topo.hub.PeerIsolationEnabled() {
		t.Fatal("isolation must default to disabled for backward compatibility")
	}
	ping := tuntest.Ping(srcB, srcA) // from spokeA, destined to spokeB
	topo.tun.spokeA.Outbound <- ping
	got := waitForPacket(t, topo.tun.spokeB.Inbound, 5*time.Second,
		"relayed packet spokeA->spokeB with isolation off")
	if len(got) != len(ping) {
		t.Fatalf("relayed packet length = %d, want %d", len(got), len(ping))
	}

	// Phase 2: enable isolation through the UAPI contract; subsequent
	// operations must follow the new rule without a restart.
	if err := topo.hub.IpcSet("peer_isolation=true\n\n"); err != nil {
		t.Fatalf("enable isolation: %v", err)
	}
	if !topo.hub.PeerIsolationEnabled() {
		t.Fatal("isolation did not become active after IpcSet")
	}
	// The get contract must report the active rule.
	if got, err := topo.hub.IpcGet(); err != nil || !strings.Contains(got, "peer_isolation=true") {
		t.Fatalf("IpcGet did not report active isolation: %q %v", got, err)
	}

	snapBefore := topo.hub.SecuritySnapshot()

	// Discard packets tee'd by the handshakes and phase-1 relay so the
	// negative assertions below only observe the isolated packet.
	drainPackets(topo.hubDelivered)
	drainPackets(topo.tun.spokeB.Inbound)

	// Phase 3: cross-peer packet must be blocked at both boundaries.
	// The inbound boundary drops it before it ever reaches the hub TUN.
	topo.tun.spokeA.Outbound <- ping
	assertNoPacket(t, topo.tun.spokeB.Inbound, 800*time.Millisecond,
		"spokeA->spokeB with isolation on")
	assertNoPacket(t, topo.hubDelivered, 400*time.Millisecond,
		"hub TUN write for isolated packet")

	snapAfter := topo.hub.SecuritySnapshot()
	if d := snapAfter.Drops[RouteDroppedPeerIsolation] - snapBefore.Drops[RouteDroppedPeerIsolation]; d == 0 {
		t.Fatal("peer isolation drop counter was not incremented")
	} else {
		t.Logf("isolation drops observed: %d", d)
	}

	// Phase 4: legitimate traffic still flows while isolation is on.
	// spokeA -> hub-local address: accepted (destination owned by no peer).
	hubPing := tuntest.Ping(netip.MustParseAddr("10.0.0.1"), srcA)
	topo.tun.spokeA.Outbound <- hubPing
	waitForPacket(t, topo.hubDelivered, 5*time.Second, "spokeA->hub egress with isolation on")

	// Spoke traffic inside its own address space stays accepted.
	ownPing := tuntest.Ping(netip.MustParseAddr("10.0.1.20"), srcA)
	topo.tun.spokeA.Outbound <- ownPing
	waitForPacket(t, topo.hubDelivered, 5*time.Second, "spokeA same-range traffic with isolation on")

	// Phase 5: disable isolation again; relay immediately works, verified
	// end-to-end by the packet arriving at spokeB's TUN.
	if err := topo.hub.IpcSet("peer_isolation=false\n\n"); err != nil {
		t.Fatalf("disable isolation: %v", err)
	}
	drainPackets(topo.tun.spokeB.Inbound)
	topo.tun.spokeA.Outbound <- ping
	waitForPacket(t, topo.tun.spokeB.Inbound, 5*time.Second,
		"relay restored after isolation disabled")
}

// TestInboundSourceOwnershipEndToEnd proves the encrypted-routing ownership
// check on the real data path: an authenticated spoke sending a packet with
// an inner source that belongs to the other spoke's AllowedIP range is
// dropped, while a correctly sourced packet passes.
func TestInboundSourceOwnershipEndToEnd(t *testing.T) {
	topo := newHubTopology(t)
	topo.establishHandshakes()

	// A packet that spokeA cryptographically delivers but whose inner
	// source is an address owned by spokeB's AllowedIP entry.
	spoofed := tuntest.Ping(netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("10.0.2.10"))
	before := topo.hub.SecuritySnapshot()
	drainPackets(topo.hubDelivered)
	topo.tun.spokeA.Outbound <- spoofed
	assertNoPacket(t, topo.hubDelivered, 800*time.Millisecond,
		"spoofed source from spokeA")
	after := topo.hub.SecuritySnapshot()
	if after.Drops[RouteDroppedUnroutable]-before.Drops[RouteDroppedUnroutable] == 0 {
		t.Fatal("expected unroutable drop counter for spoofed source")
	}

	// The same spoke with its legitimate source passes.
	legit := tuntest.Ping(netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("10.0.1.10"))
	topo.tun.spokeA.Outbound <- legit
	waitForPacket(t, topo.hubDelivered, 5*time.Second, "legitimately sourced packet")
}

// TestReservedSourceAddressEndToEnd covers the address-source boundary with
// a reserved, non-unicast source address.
func TestReservedSourceAddressEndToEnd(t *testing.T) {
	topo := newHubTopology(t)
	topo.establishHandshakes()

	before := topo.hub.SecuritySnapshot()
	// Source 0.0.0.0 is never attributable and never a valid source.
	badSrc := ipv4Packet(t, "0.0.0.0", "10.0.0.1")
	drainPackets(topo.hubDelivered)
	topo.tun.spokeA.Outbound <- badSrc
	assertNoPacket(t, topo.hubDelivered, 800*time.Millisecond, "unspecified source")
	after := topo.hub.SecuritySnapshot()
	if after.Drops[RouteDroppedBadSource]-before.Drops[RouteDroppedBadSource] == 0 {
		t.Fatal("expected bad-source drop counter")
	}

	// Multicast source hits the same boundary.
	before2 := topo.hub.SecuritySnapshot()
	mcastSrc := ipv4Packet(t, "224.0.0.1", "10.0.0.1")
	drainPackets(topo.hubDelivered)
	topo.tun.spokeA.Outbound <- mcastSrc
	assertNoPacket(t, topo.hubDelivered, 800*time.Millisecond, "multicast source")
	after2 := topo.hub.SecuritySnapshot()
	if after2.Drops[RouteDroppedBadSource]-before2.Drops[RouteDroppedBadSource] == 0 {
		t.Fatal("expected bad-source drop counter for multicast source")
	}
}

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"net/netip"
	"strings"
	"testing"

	"golang.zx2c4.com/wireguard/conn"
)

func mustPrefix(t *testing.T, s string) netip.Prefix {
	t.Helper()
	p, err := netip.ParsePrefix(s)
	if err != nil {
		t.Fatalf("parse prefix %q: %v", s, err)
	}
	return p
}

func mustAddr(t *testing.T, s string) netip.Addr {
	t.Helper()
	a, err := netip.ParseAddr(s)
	if err != nil {
		t.Fatalf("parse addr %q: %v", s, err)
	}
	return a
}

// TestClassifyAddress covers every address-family boundary that
// VerifyAddressSource relies on for its final verdict.
func TestClassifyAddress(t *testing.T) {
	tests := []struct {
		name string
		ip   string
		want AddressClass
		ok   bool
	}{
		// IPv4 boundaries
		{"v4 unspecified", "0.0.0.0", AddressUnspecified, false},
		{"v4 multicast low", "224.0.0.1", AddressMulticast, false},
		{"v4 multicast high", "239.255.255.255", AddressMulticast, false},
		{"v4 broadcast", "255.255.255.255", AddressBroadcast, false},
		{"v4 loopback", "127.0.0.1", AddressLoopback, true},
		{"v4 link local", "169.254.1.1", AddressLinkLocal, true},
		{"v4 unicast", "10.0.0.1", AddressUnicast, true},
		{"v4 boundary before multicast", "223.255.255.255", AddressUnicast, true},
		{"v4 boundary after multicast", "240.0.0.1", AddressUnicast, true},
		// IPv6 boundaries
		{"v6 unspecified", "::", AddressUnspecified, false},
		{"v6 multicast", "ff02::1", AddressMulticast, false},
		{"v6 loopback", "::1", AddressLoopback, true},
		{"v6 link local", "fe80::1", AddressLinkLocal, true},
		{"v6 unicast", "2001:db8::1", AddressUnicast, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			addr := mustAddr(t, tt.ip)
			if got := ClassifyAddress(addr); got != tt.want {
				t.Fatalf("ClassifyAddress(%s) = %s, want %s", tt.ip, got, tt.want)
			}
			class, ok := VerifyAddressSource(addr)
			if ok != tt.ok || class != tt.want {
				t.Fatalf("VerifyAddressSource(%s) = (%s, %v), want (%s, %v)",
					tt.ip, class, ok, tt.want, tt.ok)
			}
		})
	}
}

// TestLookupWithPrefix verifies that encrypted-routing attribution returns
// the exact longest-prefix entry that backs a decision, for both families,
// including overlapping prefixes owned by different peers and the
// no-match failure path.
func TestLookupWithPrefix(t *testing.T) {
	var table AllowedIPs
	peerA := &Peer{}
	peerB := &Peer{}

	table.Insert(mustPrefix(t, "10.0.0.0/24"), peerA)
	table.Insert(mustPrefix(t, "10.0.0.5/32"), peerB)
	table.Insert(mustPrefix(t, "2001:db8::/32"), peerA)
	table.Insert(mustPrefix(t, "2001:db8:1::/48"), peerB)

	tests := []struct {
		name       string
		ip         string
		wantPeer   *Peer
		wantPrefix string
	}{
		{"v4 longest prefix wins", "10.0.0.5", peerB, "10.0.0.5/32"},
		{"v4 shorter prefix", "10.0.0.9", peerA, "10.0.0.0/24"},
		{"v4 no match", "192.0.2.1", nil, ""},
		{"v6 longest prefix wins", "2001:db8:1::dead", peerB, "2001:db8:1::/48"},
		{"v6 shorter prefix", "2001:db8:2::1", peerA, "2001:db8::/32"},
		{"v6 no match", "2001:dead::1", nil, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			addr := mustAddr(t, tt.ip)
			gotPeer, gotPrefix := table.LookupWithPrefix(addr.AsSlice())
			if gotPeer != tt.wantPeer {
				t.Fatalf("peer attribution for %s = %p, want %p", tt.ip, gotPeer, tt.wantPeer)
			}
			if tt.wantPrefix == "" {
				if gotPrefix.IsValid() {
					t.Fatalf("expected zero prefix for no match, got %s", gotPrefix)
				}
				return
			}
			if gotPrefix.String() != tt.wantPrefix {
				t.Fatalf("matched prefix for %s = %s, want %s",
					tt.ip, gotPrefix, tt.wantPrefix)
			}
		})
	}

	// Lookup must keep returning the same peer as LookupWithPrefix.
	if table.Lookup(mustAddr(t, "10.0.0.5").AsSlice()) != peerB {
		t.Fatal("Lookup and LookupWithPrefix disagree")
	}
}

// newPolicyDevice builds a minimal Device carrying only the security policy
// and an AllowedIPs trie, which is all the classification functions touch.
// noopBind is installed so IpcSet operations on the device do not
// dereference a nil bind; no goroutines or sockets are created.
func newPolicyDevice(t *testing.T) *Device {
	t.Helper()
	device := &Device{log: NewLogger(LogLevelSilent, "")}
	device.net.bind = &noopBind{}
	return device
}

// noopBind satisfies conn.Bind for tests that never open a socket.
type noopBind struct{}

func (noopBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	return nil, port, nil
}
func (noopBind) Close() error                                  { return nil }
func (noopBind) SetMark(mark uint32) error                     { return nil }
func (noopBind) Send(bufs [][]byte, ep conn.Endpoint) error    { return nil }
func (noopBind) ParseEndpoint(s string) (conn.Endpoint, error) { return nil, nil }
func (noopBind) BatchSize() int                                { return 1 }

func insertAllowed(t *testing.T, device *Device, peer *Peer, prefixes ...string) {
	t.Helper()
	for _, p := range prefixes {
		device.allowedips.Insert(mustPrefix(t, p), peer)
	}
}

// ipv4Packet builds a minimally valid IPv4 packet with the given src/dst.
func ipv4Packet(t *testing.T, src, dst string) []byte {
	t.Helper()
	s := mustAddr(t, src).As4()
	d := mustAddr(t, dst).As4()
	pkt := make([]byte, ipv4HeaderLen)
	// Version 4, IHL 5 (20-byte header).
	pkt[0] = (4 << 4) | 5
	// total length
	pkt[IPv4offsetTotalLength] = 0
	pkt[IPv4offsetTotalLength+1] = byte(ipv4HeaderLen)
	copy(pkt[IPv4offsetSrc:], s[:])
	copy(pkt[IPv4offsetDst:], d[:])
	return pkt
}

// ipv6Packet builds a minimally valid IPv6 packet with the given src/dst.
func ipv6Packet(t *testing.T, src, dst string) []byte {
	t.Helper()
	s := mustAddr(t, src).As16()
	d := mustAddr(t, dst).As16()
	pkt := make([]byte, ipv6HeaderLen)
	pkt[0] = 6 << 4
	copy(pkt[IPv6offsetSrc:], s[:])
	copy(pkt[IPv6offsetDst:], d[:])
	return pkt
}

// TestClassifyInboundPacket covers the inbound decision table:
// bad source class, ownership mismatch, isolation drops and accepts.
func TestClassifyInboundPacket(t *testing.T) {
	device := newPolicyDevice(t)
	peerA := &Peer{}
	peerB := &Peer{}
	insertAllowed(t, device, peerA, "10.0.1.0/24", "2001:db8:1::/48")
	insertAllowed(t, device, peerB, "10.0.2.0/24", "2001:db8:2::/48")

	t.Run("normal v4 accepted with prefix basis", func(t *testing.T) {
		res := device.classifyInboundPacket(peerA, ipv4Packet(t, "10.0.1.7", "8.8.8.8"))
		if res.Verdict != RouteAccepted || res.Peer != peerA {
			t.Fatalf("verdict = %s peer=%v, want accepted/peerA", res.Verdict, res.Peer)
		}
		if res.MatchedPrefix.String() != "10.0.1.0/24" {
			t.Fatalf("matched prefix = %s, want 10.0.1.0/24", res.MatchedPrefix)
		}
	})

	t.Run("normal v6 accepted", func(t *testing.T) {
		res := device.classifyInboundPacket(peerB, ipv6Packet(t, "2001:db8:2::9", "2001:db8:9::1"))
		if res.Verdict != RouteAccepted || res.Peer != peerB {
			t.Fatalf("verdict = %s, want accepted/peerB", res.Verdict)
		}
		if res.MatchedPrefix.String() != "2001:db8:2::/48" {
			t.Fatalf("matched prefix = %s", res.MatchedPrefix)
		}
	})

	t.Run("spoofed source owned by another peer is unroutable", func(t *testing.T) {
		// Cryptographically from peerA, but inner source belongs to peerB.
		res := device.classifyInboundPacket(peerA, ipv4Packet(t, "10.0.2.3", "8.8.8.8"))
		if res.Verdict != RouteDroppedUnroutable {
			t.Fatalf("verdict = %s, want dropped-unroutable", res.Verdict)
		}
	})

	t.Run("unknown source with no owner is unroutable", func(t *testing.T) {
		res := device.classifyInboundPacket(peerA, ipv4Packet(t, "198.51.100.1", "8.8.8.8"))
		if res.Verdict != RouteDroppedUnroutable {
			t.Fatalf("verdict = %s, want dropped-unroutable", res.Verdict)
		}
	})

	t.Run("unspecified source rejected on class check", func(t *testing.T) {
		res := device.classifyInboundPacket(peerA, ipv4Packet(t, "0.0.0.0", "8.8.8.8"))
		if res.Verdict != RouteDroppedBadSource {
			t.Fatalf("verdict = %s, want dropped-bad-source", res.Verdict)
		}
	})

	t.Run("multicast source rejected on class check", func(t *testing.T) {
		res := device.classifyInboundPacket(peerA, ipv4Packet(t, "224.0.0.1", "8.8.8.8"))
		if res.Verdict != RouteDroppedBadSource {
			t.Fatalf("verdict = %s, want dropped-bad-source", res.Verdict)
		}
	})

	t.Run("truncated header", func(t *testing.T) {
		res := device.classifyInboundPacket(peerA, []byte{0x45, 0, 0})
		if res.Verdict != RouteDroppedTruncated {
			t.Fatalf("verdict = %s, want dropped-truncated", res.Verdict)
		}
	})

	t.Run("invalid ip version", func(t *testing.T) {
		res := device.classifyInboundPacket(peerA, []byte{0x70})
		if res.Verdict != RouteDroppedInvalidVersion {
			t.Fatalf("verdict = %s, want dropped-invalid-version", res.Verdict)
		}
	})

	t.Run("isolation off: peer-to-peer destination accepted", func(t *testing.T) {
		if device.PeerIsolationEnabled() {
			t.Fatal("isolation must default to off")
		}
		// From peerA, destined for peerB's address space: allowed while
		// isolation is disabled.
		res := device.classifyInboundPacket(peerA, ipv4Packet(t, "10.0.1.7", "10.0.2.9"))
		if res.Verdict != RouteAccepted {
			t.Fatalf("verdict = %s, want accepted with isolation off", res.Verdict)
		}
	})

	t.Run("isolation on: peer-to-peer destination dropped", func(t *testing.T) {
		device.SetPeerIsolation(true)
		defer device.SetPeerIsolation(false)
		res := device.classifyInboundPacket(peerA, ipv4Packet(t, "10.0.1.7", "10.0.2.9"))
		if res.Verdict != RouteDroppedPeerIsolation {
			t.Fatalf("verdict = %s, want dropped-peer-isolation", res.Verdict)
		}
	})

	t.Run("isolation on: same-peer destination still accepted", func(t *testing.T) {
		device.SetPeerIsolation(true)
		defer device.SetPeerIsolation(false)
		res := device.classifyInboundPacket(peerA, ipv4Packet(t, "10.0.1.7", "10.0.1.9"))
		if res.Verdict != RouteAccepted {
			t.Fatalf("verdict = %s, want accepted for same-peer traffic", res.Verdict)
		}
	})

	t.Run("isolation on: destination with no owner still accepted", func(t *testing.T) {
		device.SetPeerIsolation(true)
		defer device.SetPeerIsolation(false)
		// Traffic leaving the overlay to the public internet is not
		// peer-to-peer relay and must not be blocked by isolation.
		res := device.classifyInboundPacket(peerA, ipv4Packet(t, "10.0.1.7", "8.8.8.8"))
		if res.Verdict != RouteAccepted {
			t.Fatalf("verdict = %s, want accepted for egress traffic", res.Verdict)
		}
	})
}

// TestClassifyOutboundPacket covers the outbound decision table.
func TestClassifyOutboundPacket(t *testing.T) {
	device := newPolicyDevice(t)
	peerA := &Peer{}
	peerB := &Peer{}
	insertAllowed(t, device, peerA, "10.0.1.0/24")
	insertAllowed(t, device, peerB, "10.0.2.0/24")

	t.Run("normal routing attributes destination", func(t *testing.T) {
		res := device.classifyOutboundPacket(ipv4Packet(t, "172.16.0.1", "10.0.2.5"))
		if res.Verdict != RouteAccepted || res.Peer != peerB {
			t.Fatalf("verdict = %s peer=%v, want accepted/peerB", res.Verdict, res.Peer)
		}
		if res.MatchedPrefix.String() != "10.0.2.0/24" {
			t.Fatalf("matched prefix = %s", res.MatchedPrefix)
		}
	})

	t.Run("unroutable destination", func(t *testing.T) {
		res := device.classifyOutboundPacket(ipv4Packet(t, "172.16.0.1", "198.51.100.5"))
		if res.Verdict != RouteDroppedUnroutable {
			t.Fatalf("verdict = %s, want dropped-unroutable", res.Verdict)
		}
	})

	t.Run("malformed packets", func(t *testing.T) {
		if res := device.classifyOutboundPacket([]byte{0x50}); res.Verdict != RouteDroppedInvalidVersion {
			t.Fatalf("version verdict = %s", res.Verdict)
		}
		if res := device.classifyOutboundPacket([]byte{0x45, 0, 0}); res.Verdict != RouteDroppedTruncated {
			t.Fatalf("truncation verdict = %s", res.Verdict)
		}
		if res := device.classifyOutboundPacket(nil); res.Verdict != RouteDroppedInvalidVersion {
			t.Fatalf("empty verdict = %s", res.Verdict)
		}
	})

	t.Run("isolation off: relay from one peer space to another allowed", func(t *testing.T) {
		// Local TUN packet sourced from peerA's space going to peerB.
		res := device.classifyOutboundPacket(ipv4Packet(t, "10.0.1.9", "10.0.2.5"))
		if res.Verdict != RouteAccepted {
			t.Fatalf("verdict = %s, want accepted", res.Verdict)
		}
	})

	t.Run("isolation on: cross-peer relay dropped", func(t *testing.T) {
		device.SetPeerIsolation(true)
		defer device.SetPeerIsolation(false)
		res := device.classifyOutboundPacket(ipv4Packet(t, "10.0.1.9", "10.0.2.5"))
		if res.Verdict != RouteDroppedPeerIsolation {
			t.Fatalf("verdict = %s, want dropped-peer-isolation", res.Verdict)
		}
	})

	t.Run("isolation on: local source may still reach peers", func(t *testing.T) {
		device.SetPeerIsolation(true)
		defer device.SetPeerIsolation(false)
		// A source not owned by any peer (the hub's own address) reaching
		// a peer is legitimate hub-originated traffic.
		res := device.classifyOutboundPacket(ipv4Packet(t, "172.16.0.1", "10.0.2.5"))
		if res.Verdict != RouteAccepted {
			t.Fatalf("verdict = %s, want accepted", res.Verdict)
		}
	})
}

// TestSecurityCountersAndSwitch checks the atomic switch semantics and that
// every drop reason increments exactly its own counter.
func TestSecurityCountersAndSwitch(t *testing.T) {
	device := newPolicyDevice(t)
	peerA := &Peer{}
	insertAllowed(t, device, peerA, "10.0.1.0/24")

	if device.PeerIsolationEnabled() {
		t.Fatal("zero-value policy must have isolation disabled")
	}
	device.SetPeerIsolation(true)
	if !device.PeerIsolationEnabled() {
		t.Fatal("isolation did not switch on")
	}
	device.SetPeerIsolation(false)
	if device.PeerIsolationEnabled() {
		t.Fatal("isolation did not switch off")
	}

	before := device.SecuritySnapshot()
	device.recordDrop(RouteDroppedBadSource, "test")
	device.recordDrop(RouteDroppedBadSource, "test")
	device.recordDrop(RouteDroppedPeerIsolation, "test")
	after := device.SecuritySnapshot()

	delta := func(v RouteVerdict) uint64 {
		return after.Drops[v] - before.Drops[v]
	}
	if delta(RouteDroppedBadSource) != 2 {
		t.Fatalf("bad-source delta = %d, want 2", delta(RouteDroppedBadSource))
	}
	if delta(RouteDroppedPeerIsolation) != 1 {
		t.Fatalf("isolation delta = %d, want 1", delta(RouteDroppedPeerIsolation))
	}
	if delta(RouteDroppedUnroutable) != 0 {
		t.Fatalf("unroutable delta = %d, want 0", delta(RouteDroppedUnroutable))
	}

	// RouteAccepted must never be counted as a drop.
	device.recordDrop(RouteAccepted, "must be ignored")
	if device.SecuritySnapshot().Drops[RouteAccepted] != 0 {
		t.Fatal("accepted verdict was counted as a drop")
	}
}

// TestPeerIsolationUAPI exercises the contract surface: strict parsing of
// the new key, round-tripping through IpcGet, and immediate effect on the
// running policy.
func TestPeerIsolationUAPI(t *testing.T) {
	device := newPolicyDevice(t)

	for _, v := range []string{"true", "1", "TRUE", "True", "t"} {
		if err := device.IpcSet("peer_isolation=" + v + "\n\n"); err != nil {
			t.Fatalf("set %q: %v", v, err)
		}
		if !device.PeerIsolationEnabled() {
			t.Fatalf("value %q did not enable isolation", v)
		}
	}
	for _, v := range []string{"false", "0", "f"} {
		if err := device.IpcSet("peer_isolation=" + v + "\n\n"); err != nil {
			t.Fatalf("set %q: %v", v, err)
		}
		if device.PeerIsolationEnabled() {
			t.Fatalf("value %q did not disable isolation", v)
		}
	}

	err := device.IpcSet("peer_isolation=yes\n\n")
	if err == nil {
		t.Fatal("invalid boolean was accepted")
	}
	if !strings.Contains(err.Error(), "peer_isolation") {
		t.Fatalf("error %v does not name the offending key", err)
	}
	if ipcErr, ok := err.(*IPCError); !ok || ipcErr.ErrorCode() != -22 {
		t.Fatalf("error = %v, want IPCError with EINVAL(-22)", err)
	}

	// Round-trip through get.
	device.SetPeerIsolation(true)
	got, err := device.IpcGet()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got, "peer_isolation=true\n") {
		t.Fatalf("IpcGet output missing peer_isolation=true:\n%s", got)
	}
	device.SetPeerIsolation(false)
	got, _ = device.IpcGet()
	if !strings.Contains(got, "peer_isolation=false\n") {
		t.Fatalf("IpcGet output missing peer_isolation=false:\n%s", got)
	}
}

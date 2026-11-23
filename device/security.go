/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"net"
	"net/netip"
	"sync/atomic"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

const (
	ipv4HeaderLen = ipv4.HeaderLen
	ipv6HeaderLen = ipv6.HeaderLen
	netIPv4Len    = net.IPv4len
	netIPv6Len    = net.IPv6len
)

// This file implements the central-node security policy:
//
//  1. Peer-to-peer traffic isolation ("hub isolation"). When enabled on a
//     device that acts as a central relay node, an authenticated packet
//     received from one peer is never re-routed to another peer, and a
//     packet read from the local TUN device whose destination is owned by
//     peer A is never encrypted and sent to peer B.
//
//  2. Encrypted-routing ownership attribution. Every routing decision is
//     made through AllowedIPs.LookupWithPrefix, which reports the exact
//     AllowedIP prefix that caused the address-to-peer attribution, so the
//     basis of every accept/drop decision is explicit and reviewable.
//
//  3. Address-source verification. Inbound inner source addresses and
//     outbound inner destination addresses are only trusted when the
//     AllowedIPs trie attributes them to the cryptographic peer.
//     VerifyAddressSource additionally classifies an address against the
//     reserved IPv4/IPv6 address ranges that must never be attributed to a
//     peer as an ordinary unicast source.
//
// All switches are atomic, so a configuration or state update changes the
// rule used by every packet processed afterwards without restarting the
// device.

// AddressClass describes how an address is classified against reserved
// IP address ranges. The classification is the "address source" verdict that
// backs the source-address verification boundary.
type AddressClass uint8

const (
	// AddressUnspecified is the all-zeros address of the family
	// (0.0.0.0/32 or ::/128), which is never a valid packet source.
	AddressUnspecified AddressClass = iota
	// AddressMulticast is an IPv4 class D multicast address (224.0.0.0/4)
	// or an IPv6 multicast address (ff00::/8). Such addresses are never
	// valid as a unicast packet source.
	AddressMulticast
	// AddressBroadcast is the IPv4 limited broadcast address
	// (255.255.255.255/32). Subnet-directed broadcasts are not
	// distinguished here because the local subnet mask is not known;
	// only the limited broadcast address is universally invalid as a
	// source.
	AddressBroadcast
	// AddressLoopback is 127.0.0.0/8 (IPv4) or ::1/128 (IPv6).
	AddressLoopback
	// AddressLinkLocal is 169.254.0.0/16 (IPv4) or fe80::/10 (IPv6).
	AddressLinkLocal
	// AddressUnicast is any ordinary unicast address that may be
	// attributed to a peer through an AllowedIP entry.
	AddressUnicast
)

// String renders an AddressClass for log lines and test diagnostics.
func (c AddressClass) String() string {
	switch c {
	case AddressUnspecified:
		return "unspecified"
	case AddressMulticast:
		return "multicast"
	case AddressBroadcast:
		return "broadcast"
	case AddressLoopback:
		return "loopback"
	case AddressLinkLocal:
		return "link-local"
	case AddressUnicast:
		return "unicast"
	default:
		return "unknown"
	}
}

// ClassifyAddress returns the AddressClass of addr.
//
// The ordering matters: unspecified is checked before the other reserved
// ranges because ::/128 and 0.0.0.0/32 do not match any of them.
func ClassifyAddress(addr netip.Addr) AddressClass {
	if !addr.IsValid() {
		return AddressUnspecified
	}
	if addr.Is4() {
		if addr.IsUnspecified() {
			return AddressUnspecified
		}
		if addr.IsMulticast() {
			return AddressMulticast
		}
		b := addr.As4()
		if b[0] == 255 && b[1] == 255 && b[2] == 255 && b[3] == 255 {
			return AddressBroadcast
		}
		if b[0] == 127 {
			return AddressLoopback
		}
		if b[0] == 169 && b[1] == 254 {
			return AddressLinkLocal
		}
		return AddressUnicast
	}
	if addr.IsUnspecified() {
		return AddressUnspecified
	}
	if addr.IsMulticast() {
		return AddressMulticast
	}
	if addr.IsLoopback() {
		return AddressLoopback
	}
	if addr.IsLinkLocalUnicast() {
		return AddressLinkLocal
	}
	return AddressUnicast
}

// VerifyAddressSource classifies an inner packet source address and reports
// whether it is acceptable as an ordinary unicast source that may be
// attributed to a peer.
//
// Unspecified, multicast and (for IPv4) limited-broadcast addresses are
// rejected outright: there is no legitimate WireGuard peer that originates
// packets from them. Loopback and link-local addresses remain attributable
// because they are valid unicast sources inside deliberately configured
// overlays; rejecting them would break existing, legitimate configurations.
//
// This is the explicit address-source verification boundary; the data path
// additionally requires an AllowedIP ownership match in
// (*Device).classifyInboundPacket.
func VerifyAddressSource(addr netip.Addr) (class AddressClass, ok bool) {
	class = ClassifyAddress(addr)
	switch class {
	case AddressUnspecified, AddressMulticast, AddressBroadcast:
		return class, false
	default:
		return class, true
	}
}

// RouteVerdict identifies which rule produced a data-plane accept/drop
// decision. Every value corresponds to one boundary that a reviewer can
// check directly in security.go and at the single call sites in
// receive.go and send.go.
type RouteVerdict uint8

const (
	// RouteAccepted means the packet passed all security checks.
	RouteAccepted RouteVerdict = iota
	// RouteDroppedInvalidVersion means the inner packet carried an IP
	// version other than 4 or 6.
	RouteDroppedInvalidVersion
	// RouteDroppedTruncated means the packet was shorter than the IP
	// header its version requires, or its length field was inconsistent.
	RouteDroppedTruncated
	// RouteDroppedUnroutable means no AllowedIP entry attributed the
	// destination to any peer (outbound) or the source to the sending
	// cryptographic peer (inbound).
	RouteDroppedUnroutable
	// RouteDroppedBadSource means the source address failed
	// VerifyAddressSource (reserved non-unicast source).
	RouteDroppedBadSource
	// RouteDroppedPeerIsolation means hub isolation was enabled and the
	// packet would have crossed from one peer to another peer.
	RouteDroppedPeerIsolation
)

// String renders a RouteVerdict for log lines and test diagnostics.
func (v RouteVerdict) String() string {
	switch v {
	case RouteAccepted:
		return "accepted"
	case RouteDroppedInvalidVersion:
		return "dropped-invalid-version"
	case RouteDroppedTruncated:
		return "dropped-truncated"
	case RouteDroppedUnroutable:
		return "dropped-unroutable"
	case RouteDroppedBadSource:
		return "dropped-bad-source"
	case RouteDroppedPeerIsolation:
		return "dropped-peer-isolation"
	default:
		return "dropped-unknown"
	}
}

// SecurityStats is an immutable snapshot of the security counters, returned
// by (*Device).SecuritySnapshot. Counters are monotonically increasing for
// the lifetime of a device and are safe to read concurrently with packet
// processing.
type SecurityStats struct {
	PeerIsolationEnabled bool
	// Deltas for each drop reason; RouteAccepted is never counted.
	Drops [RouteDroppedPeerIsolation + 1]uint64
}

// securityPolicy holds the atomic central-node security state of a Device.
// The zero value is a valid, fully permissive policy (isolation disabled),
// which preserves the historical WireGuard behavior for devices that never
// set peer_isolation.
type securityPolicy struct {
	// peerIsolation is 0 when cross-peer traffic is allowed and 1 when
	// the device must isolate peers from each other. Accessed only
	// through atomic operations.
	peerIsolation atomic.Uint32

	// One counter per RouteVerdict drop reason, indexed by the verdict.
	// They are written from the sequential receiver/TUN-reader goroutines
	// but read from arbitrary goroutines via SecuritySnapshot, hence the
	// atomics.
	drops [RouteDroppedPeerIsolation + 1]atomic.Uint64
}

// PeerIsolationEnabled reports whether cross-peer traffic isolation is
// currently active. The read is atomic, so it always reflects the most
// recent IpcSet/SetPeerIsolation update.
func (device *Device) PeerIsolationEnabled() bool {
	return device.security.peerIsolation.Load() != 0
}

// SetPeerIsolation enables or disables central-node peer isolation. It is
// safe to call while the device is up and carrying traffic: the next packet
// processed after the call already observes the new rule.
func (device *Device) SetPeerIsolation(enable bool) {
	var v uint32
	if enable {
		v = 1
	}
	device.security.peerIsolation.Store(v)
	if device.log != nil && device.log.Verbosef != nil {
		device.log.Verbosef("Security: peer isolation set to %v", enable)
	}
}

// recordDrop increments the counter for verdict and logs the decision basis.
// It is called only from the two data-path decision points.
func (device *Device) recordDrop(verdict RouteVerdict, detail string) {
	if verdict == RouteAccepted {
		return
	}
	if verdict <= RouteDroppedPeerIsolation {
		device.security.drops[verdict].Add(1)
	}
	if device.log != nil && device.log.Verbosef != nil {
		device.log.Verbosef("Security: %s: %s", verdict, detail)
	}
}

// SecuritySnapshot returns the current isolation state and a copy of the
// drop counters. It allocates no per-packet memory and takes no data-path
// lock, so it can be polled from tests or management code at any time.
func (device *Device) SecuritySnapshot() SecurityStats {
	snap := SecurityStats{PeerIsolationEnabled: device.PeerIsolationEnabled()}
	for i := range device.security.drops {
		snap.Drops[i] = device.security.drops[i].Load()
	}
	return snap
}

// securityRoutingResult is the explicit basis of a routing decision. When
// Verdict is RouteAccepted, Peer is the cryptographic peer the packet is
// attributed to and MatchedPrefix is the AllowedIP entry that produced the
// attribution (the longest-prefix match).
type securityRoutingResult struct {
	Verdict       RouteVerdict
	Peer          *Peer
	MatchedPrefix netip.Prefix
}

// classifyOutboundPacket attributes a plaintext packet read from the local
// TUN device to its destination peer.
//
// The destination address bytes are taken directly from the IP header, so
// the attribution can never be influenced by anything other than the packet
// and the current AllowedIP trie. With peer isolation enabled, a packet
// whose source is attributable to a configured peer is treated as relayed
// peer traffic and may only leave for that same peer; sending it to a
// different peer would silently bridge two peers.
//
// Malformed headers (unknown IP version, truncated header) are reported with
// a precise verdict instead of being silently skipped.
func (device *Device) classifyOutboundPacket(packet []byte) securityRoutingResult {
	version, src, dst, ok := innerPacketAddresses(packet)
	if !ok {
		if version == 0 {
			return securityRoutingResult{Verdict: RouteDroppedInvalidVersion}
		}
		return securityRoutingResult{Verdict: RouteDroppedTruncated}
	}

	peer, prefix := device.allowedips.LookupWithPrefix(dst)
	if peer == nil {
		return securityRoutingResult{Verdict: RouteDroppedUnroutable}
	}

	if device.PeerIsolationEnabled() {
		srcPeer, _ := device.allowedips.LookupWithPrefix(src)
		if srcPeer != nil && srcPeer != peer {
			return securityRoutingResult{
				Verdict:       RouteDroppedPeerIsolation,
				Peer:          peer,
				MatchedPrefix: prefix,
			}
		}
	}

	return securityRoutingResult{Verdict: RouteAccepted, Peer: peer, MatchedPrefix: prefix}
}

// classifyInboundPacket attributes an authenticated, decrypted packet
// received from cryptographic peer inboundPeer to its inner source address.
//
// Two independent checks are performed, in order:
//
//  1. Address-source verification: the source address class must be an
//     acceptable unicast source (VerifyAddressSource).
//  2. Ownership verification: the AllowedIP trie must attribute the source
//     address to exactly the peer that delivered the packet. A mismatch
//     means the packet is either spoofed or belongs to a different peer's
//     address space, so it is unroutable from this peer.
//
// With peer isolation enabled, a packet whose destination is attributable
// to another configured peer is additionally dropped: accepting it would
// re-enter the TUN device and bridge the two peers through the central node.
func (device *Device) classifyInboundPacket(inboundPeer *Peer, packet []byte) securityRoutingResult {
	version, src, dst, ok := innerPacketAddresses(packet)
	if !ok {
		if version == 0 {
			return securityRoutingResult{Verdict: RouteDroppedInvalidVersion}
		}
		return securityRoutingResult{Verdict: RouteDroppedTruncated}
	}

	srcAddr, addrOK := netip.AddrFromSlice(src)
	if !addrOK || !addrOKSource(srcAddr) {
		return securityRoutingResult{Verdict: RouteDroppedBadSource}
	}

	sourcePeer, prefix := device.allowedips.LookupWithPrefix(src)
	if sourcePeer != inboundPeer {
		return securityRoutingResult{Verdict: RouteDroppedUnroutable}
	}

	if device.PeerIsolationEnabled() {
		dstPeer, _ := device.allowedips.LookupWithPrefix(dst)
		if dstPeer != nil && dstPeer != inboundPeer {
			return securityRoutingResult{
				Verdict:       RouteDroppedPeerIsolation,
				Peer:          inboundPeer,
				MatchedPrefix: prefix,
			}
		}
	}

	return securityRoutingResult{
		Verdict:       RouteAccepted,
		Peer:          inboundPeer,
		MatchedPrefix: prefix,
	}
}

// addrOKSource is a small wrapper around VerifyAddressSource so the data
// path expresses the policy name rather than the classification mechanics.
func addrOKSource(addr netip.Addr) bool {
	_, ok := VerifyAddressSource(addr)
	return ok
}

// innerPacketAddresses extracts the raw source and destination address
// bytes from an IPv4/IPv6 packet header. version is 4 or 6 on success and 0
// when the IP version is unsupported. ok is false when the packet is too
// short for its header or (for the callers' length-trimmed packets) carries
// an unsupported version.
//
// Callers in receive.go and send.go have already validated the total/payload
// length fields; this function intentionally only performs the header
// presence checks needed to read the address fields safely.
func innerPacketAddresses(packet []byte) (version uint8, src, dst []byte, ok bool) {
	if len(packet) == 0 {
		return 0, nil, nil, false
	}
	switch packet[0] >> 4 {
	case 4:
		if len(packet) < ipv4HeaderLen {
			return 4, nil, nil, false
		}
		return 4,
			packet[IPv4offsetSrc : IPv4offsetSrc+netIPv4Len],
			packet[IPv4offsetDst : IPv4offsetDst+netIPv4Len],
			true
	case 6:
		if len(packet) < ipv6HeaderLen {
			return 6, nil, nil, false
		}
		return 6,
			packet[IPv6offsetSrc : IPv6offsetSrc+netIPv6Len],
			packet[IPv6offsetDst : IPv6offsetDst+netIPv6Len],
			true
	default:
		return 0, nil, nil, false
	}
}

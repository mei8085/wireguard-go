/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package bindtest

// Tx4 returns the channel on which the bind transmits IPv4 datagrams.
// It is intended for tests that need to observe or capture sent packets.
func (c *ChannelBind) Tx4() *chan []byte { return c.tx4 }

// Tx6 returns the channel on which the bind transmits IPv6 datagrams.
func (c *ChannelBind) Tx6() *chan []byte { return c.tx6 }

// Rx4 returns the channel from which the bind receives IPv4 datagrams.
// It is intended for tests that need to inject packets as if received.
func (c *ChannelBind) Rx4() *chan []byte { return c.rx4 }

// Rx6 returns the channel from which the bind receives IPv6 datagrams.
func (c *ChannelBind) Rx6() *chan []byte { return c.rx6 }

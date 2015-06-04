// Copyright (c) 2015 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

/*
Package peer provides a common base for creating and managing bitcoin network
peers for fully validating nodes, Simplified Payment Verification (SPV) nodes,
proxies, etc. It handles all the common message handlers like initial message
version negotiation and handling and responding to pings. For other messages,
it provides a mechanism to register and manage custom handlers which will be
invoked on receiving the given message.

Creating a peer requires a method to retrieve the newest block sha, a nonce, a
channel to signal peer completion, an address manager and customizable config.
Once initialized, a peer can be started using the Start method.
*/
package peer

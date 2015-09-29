// Copyright (c) 2015 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package peer_test

import (
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/btcsuite/btcd/peer"
	"github.com/btcsuite/btcd/wire"
)

// lookupFunc is a callback which resolves IPs from the provided host string.
// In this example, a standard "ip:port" hostname is used, therefore this func
// is not implemented.
func lookupFunc(host string) ([]net.IP, error) {
	return nil, errors.New("not implemented")
}

// newestSha returns the latest known block to this peer.
// In this example, it returns a hard-coded hash and height.
func newestSha() (*wire.ShaHash, int32, error) {
	hashStr := "14a0810ac680a3eb3f82edc878cea25ec41d6b790744e5daeef"
	hash, err := wire.NewShaHashFromStr(hashStr)
	if err != nil {
		return nil, 0, err
	}
	return hash, 234439, nil
}

// mockRemotePeer creates a basic inbound peer listening on the simnet port for
// use with Example_peerConnection.  It does not return until the listner is
// active.
func mockRemotePeer() error {
	// Configure peer to act as a simnet node that offers no services.
	peerCfg := &peer.Config{
		NewestBlock:      newestSha, // Latest known block to this peer.
		UserAgentName:    "peer",    // User agent name to advertise.
		UserAgentVersion: "1.0",     // User agent version to advertise.
		Net:              wire.SimNet,
		Services:         0,
	}

	// Accept connections on the simnet port.
	listener, err := net.Listen("tcp", "127.0.0.1:18555")
	if err != nil {
		return err
	}
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			fmt.Printf("Accept: error %v\n", err)
			return
		}

		// Create and start the inbound peer.  NOTE: Ordinarily the
		// nonce wouldn't need to be changed here, however since this
		// test is faking a listener in a separate process, it needs to
		// change it in order to avoid detecting the self detection.
		p := peer.NewInboundPeer(peerCfg, conn)
		p.TstSetNonce(1)
		if err := p.Start(); err != nil {
			fmt.Printf("Start: error %v\n", err)
			return
		}
	}()

	return nil
}

// This example demonstrates the basic process for initializing and creating an
// outbound peer.  Peers negotiate by exchanging version and verack messages.
// For demonstration, a simple handler for version message is attached to the
// peer.
func Example_newOutboundPeer() {
	// Ordinarily this will not be needed since the outbound peer will be
	// connecting to a remote peer, however, since this example is executed
	// and tested, a mock remote peer is needed to listen for the outbound
	// peer.
	if err := mockRemotePeer(); err != nil {
		fmt.Printf("mockRemotePeer: unexpected error %v\n", err)
		return
	}

	// Create an outbound peer that is configured to act as a simnet node
	// that offers no services and has listeners for the version and verack
	// messages.  The verack listener is used here to signal the code below
	// when the handshake has been finished by signalling a channel.
	verack := make(chan struct{})
	peerCfg := &peer.Config{
		Listeners: &peer.MessageListeners{
			VersionListener: func(p *peer.Peer, msg *wire.MsgVersion) {
				fmt.Println("outbound: received version")
			},
			VerAckListener: func(p *peer.Peer, msg *wire.MsgVerAck) {
				verack <- struct{}{}
			},
		},

		NewestBlock:      newestSha, // Latest known block to this peer.
		UserAgentName:    "peer",    // User agent name to advertise.
		UserAgentVersion: "1.0",     // User agent version to advertise.
		Net:              wire.SimNet,
		Services:         0,
	}
	na := wire.NewNetAddressIPPort(net.IP{127, 0, 0, 1}, uint16(18555),
		peerCfg.Services)
	p := peer.NewOutboundPeer(peerCfg, na)

	// Establish the connection to the peer address and mark it connected.
	conn, err := net.Dial("tcp", p.Addr())
	if err != nil {
		fmt.Printf("net.Dial: error %v\n", err)
		return
	}
	if err := p.Connect(conn); err != nil {
		fmt.Printf("Connect: error %v\n", err)
		return
	}

	// Wait for the verack message or timeout in case of failure.
	select {
	case <-verack:
	case <-time.After(time.Second * 1):
		fmt.Printf("Example_peerConnection: verack timeout")
	}

	// Shutdown the peer.
	p.Shutdown()

	// Output:
	// outbound: received version
}

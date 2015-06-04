// Copyright (c) 2015 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package peer_test

import (
	"errors"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/btcsuite/btcd/addrmgr"
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

// This example demonstrates initializing both inbound and outbound peers.  An
// inbound peer listening on simnet port i.e 18555 is started first, then an
// outbound peer is connected to it.
// Peers negotiate protocol by exchanging version and verack messages.  For
// demonstration, a simple handler for version message is attached to both
// peers.
func Example_peerConnection() {
	addrMgr := addrmgr.New("test", lookupFunc)
	// Configure peers to act as a simnet full node.
	peerCfg := &peer.Config{
		// Way to get the latest known block to this peer.
		NewestBlock: newestSha,
		// Way to get the most appropriate local address.
		BestLocalAddress: addrMgr.GetBestLocalAddress,
		// User agent details to advertise.
		UserAgentName:    "peer",
		UserAgentVersion: "1.0",
		// Network and service flag to use.
		Net:      wire.SimNet,
		Services: wire.SFNodeNetwork,
	}
	// Chan to sync the outbound and inbound peers.
	listening := make(chan error)
	go func() {
		// Accept connections on the simnet port.
		l1, err := net.Listen("tcp", "127.0.0.1:18555")
		if err != nil {
			listening <- err
			return
		}
		// Signal that we are listening for connections.
		listening <- nil
		c1, err := l1.Accept()
		if err != nil {
			log.Fatalf("Listen: error %v\n", err)
		}

		// Get a nonce for the inbound peer.
		nonce, err := wire.RandomUint64()
		if err != nil {
			log.Fatalf("wire.RandomUint64 err: %v", err)
		}
		// Start the inbound peer.
		p1 := peer.NewInboundPeer(peerCfg, nonce, c1)
		// Add a listener for version message.
		// Listeners are identified by the provided string so they can be
		// removed later, if required.
		p1.AddVersionMsgListener("handleVersionMsg", func(p *peer.Peer, msg *wire.MsgVersion) {
			fmt.Println("inbound: received version")
		})
		err = p1.Start()
		if err != nil {
			fmt.Printf("Start: error %v\n", err)
			return
		}
	}()
	// Get a nonce for the outbound peer.
	nonce, err := wire.RandomUint64()
	if err != nil {
		fmt.Printf("wire.RandomUint64 err: %v", err)
		return
	}
	// Get a network address for use with the outbound peer.
	na, err := addrMgr.HostToNetAddress("127.0.0.1", uint16(18555), peerCfg.Services)
	if err != nil {
		fmt.Printf("HostToNetAddress: error %v\n", err)
		return
	}
	// Wait until the inbound peer is listening for connections.
	err = <-listening
	if err != nil {
		fmt.Printf("Listen: error %v\n", err)
		return
	}
	// Start the outbound peer.
	p2 := peer.NewOutboundPeer(peerCfg, nonce, na)
	go func() {
		conn, err := net.Dial("tcp", p2.Addr())
		if err != nil {
			fmt.Printf("btcDial: error %v\n", err)
			return
		}
		if err := p2.Connect(conn); err != nil {
			fmt.Printf("Connect: error %v\n", err)
			return
		}
	}()
	// Add a listener for version message.
	p2.AddVersionMsgListener("handleVersionMsg", func(p *peer.Peer, msg *wire.MsgVersion) {
		fmt.Println("outbound: received version")
	})
	// Wait until verack is received to finish the handshake. To do this, we
	// add a verack listener on the outbound peer and use a chan to sync.
	verack := make(chan struct{})
	p2.AddVerAckMsgListener("handleVerAckMsg", func(p *peer.Peer, msg *wire.MsgVerAck) {
		verack <- struct{}{}
	})
	// In case something goes wrong, timeout.
	select {
	case <-verack:
	case <-time.After(time.Second * 1):
		fmt.Printf("Example_peerConnection: verack timeout")
	}
	// Output:
	// inbound: received version
	// outbound: received version
}

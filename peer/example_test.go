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

// zeroHash is the zero value hash (all zeros).  It is defined as a convenience.
var zeroHash wire.ShaHash

// Not implemented.
func lookupFunc(host string) ([]net.IP, error) {
	return nil, errors.New("not implemented")
}

// newestSha returns the latest known block to this peer.  It returns a
// hard-coded hash and height since this is only used for example code.
func newestSha() (*wire.ShaHash, int32, error) {
	hashStr := "14a0810ac680a3eb3f82edc878cea25ec41d6b790744e5daeef"
	hash, err := wire.NewShaHashFromStr(hashStr)
	if err != nil {
		return nil, 0, err
	}
	return hash, 234439, nil
}

// This example demonstrates initializing both inbound and outbound peers.  An
// inbound peer listening on mainnet port i.e 8333 is started first, then an
// outbound peer is connected to it.
// Peers negotiate protocol by exchanging version and verack messages.  For
// demonstration, a simple handler for version message is attached to both
// peers.
func Example_peerConnection() {
	addrMgr := addrmgr.New("test", lookupFunc)

	// Configure peers to act as a mainnet full node.
	peerCfg := &peer.Config{
		// Way to get the latest known block to this peer.
		NewestBlock: newestSha,
		// Way to get the most appropriate local address.
		BestLocalAddress: addrMgr.GetBestLocalAddress,
		// User agent details to advertise.
		UserAgentName:    "peer",
		UserAgentVersion: "1.0",
		// Network and service flag to use.
		Net:      wire.MainNet,
		Services: wire.SFNodeNetwork,
	}

	// Chan to sync the outbound and inbound peers.
	listening := make(chan error)
	go func() {
		// Accept connections on the mainnet port
		l1, err := net.Listen("tcp", "127.0.0.1:8333")
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

		// Get a nonce for the inbound peer
		nonce, err := wire.RandomUint64()
		if err != nil {
			log.Fatalf("wire.RandomUint64 err: %v", err)
		}
		// Start the inbound peer.
		p1 := peer.NewInboundPeer(peerCfg, nonce, c1)
		p1.AddVersionMsgListener("handleVersionMsg", func(p *peer.Peer, msg *wire.MsgVersion) {
			fmt.Println("inbound: received version")
		})
		err = p1.Start()
		if err != nil {
			fmt.Printf("Start: error %v\n", err)
			return
		}
	}()

	// Get a nonce for the outbound peer
	nonce, err := wire.RandomUint64()
	if err != nil {
		fmt.Printf("wire.RandomUint64 err: %v", err)
		return
	}

	// Get a network address for use with the outbound peer.
	na, err := addrMgr.HostToNetAddress("127.0.0.1", uint16(8333), wire.SFNodeNetwork)
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
		conn, err := net.Dial("tcp", "127.0.0.1:8333")
		if err != nil {
			fmt.Printf("btcDial: error %v\n", err)
			return
		}
		if err := p2.Connect(conn); err != nil {
			fmt.Printf("Connect: error %v\n", err)
			return
		}
	}()
	p2.AddVersionMsgListener("handleVersionMsg", func(p *peer.Peer, msg *wire.MsgVersion) {
		fmt.Println("outbound: received version")
	})

	// Wait a sec for the protocol negotiations and message exchanges.
	time.AfterFunc(time.Second, func() {
		p2.Shutdown()
	})
	p2.WaitForShutdown()
	// Output:
	// inbound: received version
	// outbound: received version
}

// Copyright (c) 2015 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package peer_test

import (
	"errors"
	"fmt"
	"log"
	"net"
	"strconv"
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
	peerCfg := &peer.Config{
		NewestBlock:      newestSha,
		BestLocalAddress: addrMgr.GetBestLocalAddress,
		UserAgentName:    "peer",
		UserAgentVersion: "1.0",
		Net:              wire.MainNet,
		Services:         wire.SFNodeNetwork,
	}
	listening := make(chan error)
	go func() {
		l1, err := net.Listen("tcp", "127.0.0.1:8333")
		if err != nil {
			listening <- err
			return
		}
		listening <- nil
		c1, err := l1.Accept()
		if err != nil {
			log.Fatalf("Listen: error %v\n", err)
		}
		nonce, err := wire.RandomUint64()
		if err != nil {
			log.Fatalf("wire.RandomUint64 err: %v", err)
		}
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
	err := <-listening
	if err != nil {
		fmt.Printf("Listen: error %v\n", err)
		return
	}
	nonce, err := wire.RandomUint64()
	if err != nil {
		fmt.Printf("wire.RandomUint64 err: %v", err)
		return
	}
	host, portStr, err := net.SplitHostPort("127.0.0.1:8333")
	if err != nil {
		fmt.Printf("SplitHostPort: error %v\n", err)
		return
	}

	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		fmt.Printf("ParseUint: error %v\n", err)
		return
	}
	na, err := addrMgr.HostToNetAddress(host, uint16(port), 0)
	if err != nil {
		fmt.Printf("HostToNetAddress: error %v\n", err)
		return
	}
	p2 := peer.NewOutboundPeer(peerCfg, nonce, na)
	go func() {
		conn, err := net.Dial("tcp", "127.0.0.1:8333")
		if err != nil {
			fmt.Printf("btcDial: error %v\n", err)
		}
		p2.Connect(conn)
	}()
	p2.AddVersionMsgListener("handleVersionMsg", func(p *peer.Peer, msg *wire.MsgVersion) {
		fmt.Println("outbound: received version")
	})
	time.AfterFunc(time.Second, func() {
		p2.Shutdown()
	})
	p2.WaitForShutdown()
	// Output:
	// inbound: received version
	// outbound: received version
}

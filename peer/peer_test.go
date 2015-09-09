// Copyright (c) 2015 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package peer_test

import (
	"bytes"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/btcsuite/btcd/addrmgr"
	"github.com/btcsuite/btcd/peer"
	"github.com/btcsuite/btcd/wire"
)

// conn mocks a network connection by implementing the net.Conn interface.  It
// is used to test peer connection without actually opening a network
// connection.
type conn struct {
	io.Reader
	io.Writer
	io.Closer

	// local network, address for the connection.
	lnet, laddr string

	// remote network, address for the connection.
	rnet, raddr string
}

// LocalAddr returns the local address for the connection.
func (c conn) LocalAddr() net.Addr {
	return &addr{c.lnet, c.laddr}
}

// Remote returns the remote address for the connection.
func (c conn) RemoteAddr() net.Addr {
	return &addr{c.rnet, c.raddr}
}

// Close handles closing the connection.
func (c conn) Close() error {
	return nil
}

func (c conn) SetDeadline(t time.Time) error      { return nil }
func (c conn) SetReadDeadline(t time.Time) error  { return nil }
func (c conn) SetWriteDeadline(t time.Time) error { return nil }

// addr mocks a network address
type addr struct {
	net, address string
}

func (m addr) Network() string { return m.net }
func (m addr) String() string  { return m.address }

// pipe turns two mock connections into a full-duplex connection similar to
// net.Pipe to allow pipe's with (fake) addresses.
func pipe(c1, c2 *conn) (*conn, *conn) {
	r1, w1 := io.Pipe()
	r2, w2 := io.Pipe()

	c1.Writer = w1
	c2.Reader = r1
	c1.Reader = r2
	c2.Writer = w2

	return c1, c2
}

// addrMgr is the test address manager.
// It is global so as to be accessible from mock listeners.
var addrMgr = addrmgr.New("test", lookupFunc)

// TestPeerConnection tests the activity between inbound and outbound peers
// using a mock connection.
func TestPeerConnection(t *testing.T) {
	peerCfg := &peer.Config{
		NewestBlock:      newestSha,
		BestLocalAddress: addrMgr.GetBestLocalAddress,
		UserAgentName:    "peer",
		UserAgentVersion: "1.0",
		Net:              wire.MainNet,
		Services:         wire.SFNodeNetwork,
	}
	c1, c2 := pipe(
		&conn{raddr: "127.0.0.1:8333"},
		&conn{raddr: "127.0.0.1:8333"},
	)

	p1 := peer.NewInboundPeer(peerCfg, 0, c1)
	err := p1.Start()
	if err != nil {
		t.Errorf("Start: error %v", err)
		return
	}

	na, err := addrMgr.HostToNetAddress("127.0.0.1", uint16(8333), wire.SFNodeNetwork)
	if err != nil {
		t.Errorf("HostToNetAddress: error %v\n", err)
		return
	}
	p2 := peer.NewOutboundPeer(peerCfg, 1, na)
	if err := p2.Connect(c2); err != nil {
		t.Errorf("Connect: error %v\n", err)
		return
	}

	time.Sleep(time.Second)

	// Test peer flags and stats
	testPeer(t, p1, true)
	testPeer(t, p2, false)
}

// testPeer tests the given peer's flags and stats
func testPeer(t *testing.T, p *peer.Peer, inbound bool) {
	wantID := int32(1)
	wantAddr := "127.0.0.1:8333"
	wantUserAgent := "/btcwire:0.2.0/peer:1.0/"
	wantInbound := true
	wantServices := wire.SFNodeNetwork
	wantProtocolVersion := uint32(70002)
	wantConnected := true
	wantVersionKnown := true
	wantLastBlock := int32(234439)
	wantStartingHeight := int32(234439)
	wantLastPingNonce := uint64(0)
	wantLastPingMicros := int64(0)
	wantTimeOffset := int64(0)

	if !inbound {
		wantID = 2
		wantInbound = false
	}

	if p.ID() != wantID {
		t.Errorf("testPeer: wrong ID - got %v, want %v", p.ID(), wantID)
		return
	}

	if p.Addr() != wantAddr {
		t.Errorf("testPeer: wrong Addr - got %v, want %v", p.Addr(), wantAddr)
		return
	}

	if p.UserAgent() != wantUserAgent {
		t.Errorf("testPeer: wrong UserAgent - got %v, want %v", p.UserAgent(), wantUserAgent)
		return
	}

	if p.Inbound() != wantInbound {
		t.Errorf("testPeer: wrong Inbound - got %v, want %v", p.Inbound(), wantInbound)
		return
	}

	if p.Services() != wantServices {
		t.Errorf("testPeer: wrong Services - got %v, want %v", p.Services(), wantServices)
		return
	}

	if p.LastPingNonce() != wantLastPingNonce {
		t.Errorf("testPeer: wrong LastPingNonce - got %v, want %v", p.LastPingNonce(), wantLastPingNonce)
		return
	}

	if p.LastPingMicros() != wantLastPingMicros {
		t.Errorf("testPeer: wrong LastPingMicros - got %v, want %v", p.LastPingMicros(), wantLastPingMicros)
		return
	}

	if p.VersionKnown() != wantVersionKnown {
		t.Errorf("testPeer: wrong VersionKnown - got %v, want %v", p.VersionKnown(), wantVersionKnown)
		return
	}

	if p.ProtocolVersion() != wantProtocolVersion {
		t.Errorf("testPeer: wrong ProtocolVersion - got %v, want %v", p.ProtocolVersion(), wantProtocolVersion)
		return
	}

	if p.LastBlock() != wantLastBlock {
		t.Errorf("testPeer: wrong LastBlock - got %v, want %v", p.LastBlock(), wantLastBlock)
		return
	}

	if p.TimeOffset() != wantTimeOffset {
		t.Errorf("testPeer: wrong TimeOffset - got %v, want %v", p.TimeOffset(), wantTimeOffset)
		return
	}

	if p.StartingHeight() != wantStartingHeight {
		t.Errorf("testPeer: wrong StartingHeight - got %v, want %v", p.StartingHeight(), wantStartingHeight)
		return
	}

	if p.Connected() != wantConnected {
		t.Errorf("testPeer: wrong Connected - got %v, want %v", p.Connected(), wantConnected)
		return
	}

	stats := p.StatsSnapshot()

	if stats.ID != wantID {
		t.Errorf("testPeer: wrong ID - got %v, want %v", stats.ID, wantID)
		return
	}

}

// TestPeer tests that the peer works as expected.
func TestOutboundPeer(t *testing.T) {
	// Use a mock NewestBlock func to test errs
	var errBlockNotFound = errors.New("newest block not found")
	var mockNewestSha = func() (*wire.ShaHash, int32, error) {
		return nil, 0, errBlockNotFound
	}

	peerCfg := &peer.Config{
		NewestBlock:      mockNewestSha,
		BestLocalAddress: addrMgr.GetBestLocalAddress,
		UserAgentName:    "peer",
		UserAgentVersion: "1.0",
		Net:              wire.MainNet,
		Services:         wire.SFNodeNetwork,
	}

	var b bytes.Buffer
	c := &conn{raddr: "127.0.0.1:8333", Writer: &b, Reader: &b}

	na, err := addrMgr.HostToNetAddress("127.0.0.1", uint16(8333), wire.SFNodeNetwork)
	if err != nil {
		t.Errorf("HostToNetAddress: error %v\n", err)
		return
	}
	p := peer.NewOutboundPeer(peerCfg, 1, na)

	if p.NA() != na {
		t.Errorf("TestOutboundPeer: wrong NA - got %v, want %v", p.NA(), na)
		return
	}

	// Test Connect err
	wantErr := errBlockNotFound
	if err := p.Connect(c); err != wantErr {
		t.Errorf("Connect: expected err %v, got %v\n", wantErr, err)
		return
	}
	// Test already started
	if err := p.Start(); err != nil {
		t.Errorf("Start: unexpected err %v\n", err)
		return
	}

	// Test Queue Inv
	fakeBlockHash := &wire.ShaHash{0x00, 0x01}
	fakeInv := wire.NewInvVect(wire.InvTypeBlock, fakeBlockHash)
	p.QueueInventory(fakeInv)
	p.AddKnownInventory(fakeInv)
	p.QueueInventory(fakeInv)

	// Test Queue Message
	fakeMsg := wire.NewMsgVerAck()
	p.QueueMessage(fakeMsg, nil)
	done := make(chan struct{})
	p.QueueMessage(fakeMsg, done)
	p.Shutdown()

	// Reset NewestBlock to normal Start
	peerCfg.NewestBlock = newestSha
	p1 := peer.NewOutboundPeer(peerCfg, 1, na)
	if err := p1.Connect(c); err != nil {
		t.Errorf("Connect: unexpected err %v\n", err)
		return
	}

	// Test update latest block
	latestBlockSha, err := wire.NewShaHashFromStr("1a63f9cdff1752e6375c8c76e543a71d239e1a2e5c6db1aa679")
	if err != nil {
		t.Errorf("NewShaHashFromStr: unexpected err %v\n", err)
		return
	}
	p1.UpdateLastAnnouncedBlock(latestBlockSha)
	p1.UpdateLastBlockHeight(234440)

	// Test Queue Inv after connection
	p1.QueueInventory(fakeInv)
	p1.Shutdown()

	// Test regression
	peerCfg.RegressionTest = true
	p2 := peer.NewOutboundPeer(peerCfg, 1, na)
	if err := p2.Connect(c); err != nil {
		t.Errorf("Connect: unexpected err %v\n", err)
		return
	}

	// Test Queue Messages
	p2.QueueMessage(wire.NewMsgGetAddr(), nil)
	p2.QueueMessage(wire.NewMsgPing(1), nil)
	p2.QueueMessage(wire.NewMsgMemPool(), nil)
	p2.QueueMessage(wire.NewMsgGetData(), nil)
	p2.QueueMessage(wire.NewMsgGetHeaders(), done)

	time.Sleep(time.Second)
	p2.Shutdown()
}

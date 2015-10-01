// Copyright (c) 2015 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package peer_test

import (
	"errors"
	"io"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/peer"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/go-socks/socks"
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

	// mocks socks proxy if true
	proxy bool
}

// LocalAddr returns the local address for the connection.
func (c conn) LocalAddr() net.Addr {
	return &addr{c.lnet, c.laddr}
}

// Remote returns the remote address for the connection.
func (c conn) RemoteAddr() net.Addr {
	if !c.proxy {
		return &addr{c.rnet, c.raddr}
	}
	host, strPort, _ := net.SplitHostPort(c.raddr)
	port, _ := strconv.Atoi(strPort)
	return &socks.ProxiedAddr{
		Net:  c.rnet,
		Host: host,
		Port: port,
	}
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

// peerStats holds the expected peer stats used for testing peer.
type peerStats struct {
	wantID              int32
	wantAddr            string
	wantUserAgent       string
	wantInbound         bool
	wantServices        wire.ServiceFlag
	wantProtocolVersion uint32
	wantConnected       bool
	wantVersionKnown    bool
	wantVerAckReceived  bool
	wantLastBlock       int32
	wantStartingHeight  int32
	wantLastPingTime    time.Time
	wantLastPingNonce   uint64
	wantLastPingMicros  int64
	wantTimeOffset      int64
}

// testPeer tests the given peer's flags and stats
func testPeer(t *testing.T, p *peer.Peer, s peerStats) {
	if p.Addr() != s.wantAddr {
		t.Errorf("testPeer: wrong Addr - got %v, want %v", p.Addr(), s.wantAddr)
		return
	}

	if p.UserAgent() != s.wantUserAgent {
		t.Errorf("testPeer: wrong UserAgent - got %v, want %v", p.UserAgent(), s.wantUserAgent)
		return
	}

	if p.Services() != s.wantServices {
		t.Errorf("testPeer: wrong Services - got %v, want %v", p.Services(), s.wantServices)
		return
	}

	if !p.LastPingTime().Equal(s.wantLastPingTime) {
		t.Errorf("testPeer: wrong LastPingTime - got %v, want %v", p.LastPingTime(), s.wantLastPingTime)
		return
	}

	if p.LastPingNonce() != s.wantLastPingNonce {
		t.Errorf("testPeer: wrong LastPingNonce - got %v, want %v", p.LastPingNonce(), s.wantLastPingNonce)
		return
	}

	if p.LastPingMicros() != s.wantLastPingMicros {
		t.Errorf("testPeer: wrong LastPingMicros - got %v, want %v", p.LastPingMicros(), s.wantLastPingMicros)
		return
	}

	if p.VerAckReceived() != s.wantVerAckReceived {
		t.Errorf("testPeer: wrong VerAckReceived - got %v, want %v", p.VerAckReceived(), s.wantVerAckReceived)
		return
	}

	if p.VersionKnown() != s.wantVersionKnown {
		t.Errorf("testPeer: wrong VersionKnown - got %v, want %v", p.VersionKnown(), s.wantVersionKnown)
		return
	}

	if p.ProtocolVersion() != s.wantProtocolVersion {
		t.Errorf("testPeer: wrong ProtocolVersion - got %v, want %v", p.ProtocolVersion(), s.wantProtocolVersion)
		return
	}

	if p.LastBlock() != s.wantLastBlock {
		t.Errorf("testPeer: wrong LastBlock - got %v, want %v", p.LastBlock(), s.wantLastBlock)
		return
	}

	if p.TimeOffset() != s.wantTimeOffset {
		t.Errorf("testPeer: wrong TimeOffset - got %v, want %v", p.TimeOffset(), s.wantTimeOffset)
		return
	}

	if p.StartingHeight() != s.wantStartingHeight {
		t.Errorf("testPeer: wrong StartingHeight - got %v, want %v", p.StartingHeight(), s.wantStartingHeight)
		return
	}

	if p.Connected() != s.wantConnected {
		t.Errorf("testPeer: wrong Connected - got %v, want %v", p.Connected(), s.wantConnected)
		return
	}

	// TODO: actually test the following methods
	p.LastSend()
	p.LastRecv()
	p.TimeConnected()
	p.BytesSent()
	p.BytesReceived()
	p.StatsSnapshot()
}

// TestPeerConnection tests connection between inbound and outbound peers.
func TestPeerConnection(t *testing.T) {
	verack := make(chan struct{}, 1)
	peerCfg := &peer.Config{
		Listeners: peer.MessageListeners{
			OnVerAck: func(p *peer.Peer, msg *wire.MsgVerAck) {
				verack <- struct{}{}
			},
		},
		UserAgentName:    "peer",
		UserAgentVersion: "1.0",
		ChainParams:      &chaincfg.MainNetParams,
		Services:         0,
	}
	inConn, outConn := pipe(
		&conn{raddr: "10.0.0.1:8333"},
		&conn{raddr: "10.0.0.2:8333"},
	)
	na := wire.NewNetAddressIPPort(net.IP{10, 0, 0, 1}, uint16(8333), 0)
	wantStats := peerStats{
		wantAddr:            "10.0.0.1:8333",
		wantUserAgent:       wire.DefaultUserAgent + "peer:1.0/",
		wantInbound:         true,
		wantServices:        0,
		wantProtocolVersion: peer.MaxProtocolVersion,
		wantConnected:       true,
		wantVersionKnown:    true,
		wantVerAckReceived:  true,
		wantLastPingTime:    *new(time.Time),
		wantLastPingNonce:   uint64(0),
		wantLastPingMicros:  int64(0),
		wantTimeOffset:      int64(0),
	}
	tests := []struct {
		name  string
		setup func() (*peer.Peer, *peer.Peer, error)
	}{{
		"handshake",
		func() (*peer.Peer, *peer.Peer, error) {
			inPeer := peer.NewInboundPeer(peerCfg, inConn)
			err := inPeer.Start()
			if err != nil {
				return nil, nil, err
			}
			outPeer := peer.NewOutboundPeer(peerCfg, na)
			if err := outPeer.Connect(outConn); err != nil {
				return nil, nil, err
			}
			for i := 0; i < 2; i++ {
				select {
				case <-verack:
				case <-time.After(time.Second * 1):
					return nil, nil, errors.New("verack timeout")
				}
			}
			return inPeer, outPeer, nil
		},
	}}
	t.Logf("Running %d tests", len(tests))
	for i, test := range tests {
		inPeer, outPeer, err := test.setup()
		if err != nil {
			t.Errorf("TestPeerConnection setup #%d: unexpected err %v\n", i, err)
			return
		}
		testPeer(t, inPeer, wantStats)
		testPeer(t, outPeer, wantStats)

		inPeer.Shutdown()
		outPeer.Shutdown()
	}
}

// TestOutboundPeer tests that the outbound peer works as expected.
func TestOutboundPeer(t *testing.T) {
	// Use a mock NewestBlock func to test errs
	var errBlockNotFound = errors.New("newest block not found")
	var mockNewestSha = func() (*wire.ShaHash, int32, error) {
		return nil, 0, errBlockNotFound
	}

	peerCfg := &peer.Config{
		NewestBlock:      mockNewestSha,
		UserAgentName:    "peer",
		UserAgentVersion: "1.0",
		ChainParams:      &chaincfg.MainNetParams,
		Services:         0,
	}

	r, w := io.Pipe()
	c := &conn{raddr: "10.0.0.1:8333", Writer: w, Reader: r}

	na := wire.NewNetAddressIPPort(net.IP{10, 0, 0, 1}, uint16(8333), 0)
	p := peer.NewOutboundPeer(peerCfg, na)
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
	done := make(chan struct{}, 5)
	p.QueueMessage(fakeMsg, done)
	<-done
	p.Shutdown()

	// Test NewestBlock
	var newestBlock = func() (*wire.ShaHash, int32, error) {
		hashStr := "14a0810ac680a3eb3f82edc878cea25ec41d6b790744e5daeef"
		hash, err := wire.NewShaHashFromStr(hashStr)
		if err != nil {
			return nil, 0, err
		}
		return hash, 234439, nil
	}
	peerCfg.NewestBlock = newestBlock
	p1 := peer.NewOutboundPeer(peerCfg, na)
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
	if p1.LastAnnouncedBlock() != latestBlockSha {
		t.Errorf("LastAnnouncedBlock: wrong block - got %v, want %v",
			p1.LastAnnouncedBlock(), latestBlockSha)
		return
	}

	// Test Queue Inv after connection
	p1.QueueInventory(fakeInv)
	p1.Shutdown()

	// Test regression
	peerCfg.ChainParams = &chaincfg.RegressionNetParams
	p2 := peer.NewOutboundPeer(peerCfg, na)
	if err := p2.Connect(c); err != nil {
		t.Errorf("Connect: unexpected err %v\n", err)
		return
	}

	// Test PushXXX
	var addrs []*wire.NetAddress
	for i := 0; i < 5; i++ {
		na := wire.NetAddress{}
		addrs = append(addrs, &na)
	}
	if err := p2.PushAddrMsg(addrs); err != nil {
		t.Errorf("PushAddrMsg: unexpected err %v\n", err)
		return
	}
	if err := p2.PushGetBlocksMsg(nil, &wire.ShaHash{}); err != nil {
		t.Errorf("PushGetBlocksMsg: unexpected err %v\n", err)
		return
	}
	if err := p2.PushGetHeadersMsg(nil, &wire.ShaHash{}); err != nil {
		t.Errorf("PushGetHeadersMsg: unexpected err %v\n", err)
		return
	}
	p2.PushRejectMsg("block", wire.RejectMalformed, "malformed", nil, true)
	p2.PushRejectMsg("block", wire.RejectInvalid, "invalid", nil, false)

	// Test Queue Messages
	p2.QueueMessage(wire.NewMsgGetAddr(), done)
	p2.QueueMessage(wire.NewMsgPing(1), done)
	p2.QueueMessage(wire.NewMsgMemPool(), done)
	p2.QueueMessage(wire.NewMsgGetData(), done)
	p2.QueueMessage(wire.NewMsgGetHeaders(), done)

	p2.Shutdown()
}

func init() {
	// Allow self connection when running the tests.
	peer.TstAllowSelfConns()
}

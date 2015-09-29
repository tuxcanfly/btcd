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

	"github.com/btcsuite/btcd/addrmgr"
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

// addrMgr is the test address manager.
// It is global so as to be accessible from mock listeners.
var addrMgr = addrmgr.New("test", lookupFunc)

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
	na, err := addrMgr.HostToNetAddress("127.0.0.1", uint16(8333), peerCfg.Services)
	if err != nil {
		t.Errorf("HostToNetAddress: unexpected err %v\n", err)
		return
	}

	wantStats := peerStats{
		wantID:              0,
		wantAddr:            "127.0.0.1:8333",
		wantUserAgent:       wire.DefaultUserAgent + "peer:1.0/",
		wantInbound:         true,
		wantServices:        wire.SFNodeNetwork,
		wantProtocolVersion: peer.MaxProtocolVersion,
		wantConnected:       true,
		wantVersionKnown:    true,
		wantVerAckReceived:  true,
		wantLastBlock:       int32(234439),
		wantStartingHeight:  int32(234439),
		wantLastPingTime:    *new(time.Time),
		wantLastPingNonce:   uint64(0),
		wantLastPingMicros:  int64(0),
		wantTimeOffset:      int64(0),
	}

	tests := []struct {
		name             string
		getPeers         func() (*peer.Peer, *peer.Peer, error)
		getInboundStats  func(s peerStats) peerStats
		getOutboundStats func(s peerStats) peerStats
	}{
		{
			"basic handshake",
			func() (*peer.Peer, *peer.Peer, error) {
				c1, c2 := pipe(
					&conn{raddr: "127.0.0.1:8333"},
					&conn{raddr: "127.0.0.1:8333"},
				)
				p1 := peer.NewInboundPeer(peerCfg, 0, c1)
				err := p1.Start()
				if err != nil {
					return nil, nil, err
				}
				p2 := peer.NewOutboundPeer(peerCfg, 1, na)
				if err := p2.Connect(c2); err != nil {
					return nil, nil, err
				}
				return p1, p2, nil
			},
			func(ps peerStats) peerStats {
				ps.wantID = 1
				return ps
			},
			func(ps peerStats) peerStats {
				ps.wantID = 2
				return ps
			},
		},
		{
			"proxied inbound connection",
			func() (*peer.Peer, *peer.Peer, error) {
				// Pass a mock proxied connection to the inbound peer
				c1, c2 := pipe(
					&conn{raddr: ":8333", proxy: true},
					&conn{raddr: "127.0.0.1:8333"},
				)
				p1 := peer.NewInboundPeer(peerCfg, 0, c1)
				err := p1.Start()
				if err != nil {
					return nil, nil, err
				}
				p2 := peer.NewOutboundPeer(peerCfg, 1, na)
				if err := p2.Connect(c2); err != nil {
					return nil, nil, err
				}
				return p1, p2, nil
			},
			func(ps peerStats) peerStats {
				ps.wantAddr = ":8333"
				ps.wantID = 3
				return ps
			},
			func(ps peerStats) peerStats {
				ps.wantID = 4
				return ps
			},
		},
	}
	t.Logf("Running %d tests", len(tests))
	for i, test := range tests {
		t.Logf("Running test: %s", test.name)
		p1, p2, err := test.getPeers()
		if err != nil {
			t.Errorf("TestPeerConnection: #%d %s unexpected err - %v",
				i, test.name, err)
			continue
		}

		// Wait until veracks are exchanged
		ready := make(chan struct{}, 1)
		p1.AddVerAckMsgListener("handleVerAckMsg", func(p *peer.Peer,
			msg *wire.MsgVerAck) {
			ready <- struct{}{}
		})
		p2.AddVerAckMsgListener("handleVerAckMsg", func(p *peer.Peer,
			msg *wire.MsgVerAck) {
			ready <- struct{}{}
		})
		for i := 0; i < 2; i++ {
			select {
			case <-ready:
			case <-time.After(time.Second * 1):
				t.Errorf("TestPeerConnection: #%d - verack timeout", i)
				continue
			}
		}

		// Test peer flags and stats
		testPeer(t, p1, test.getInboundStats(wantStats))
		testPeer(t, p2, test.getOutboundStats(wantStats))

		if p1.Inbound() != true {
			t.Errorf("testPeer: wrong Inbound - want true")
			return
		}
		if p2.Inbound() != false {
			t.Errorf("testPeer: wrong Inbound - want false")
			return
		}

		// Test listeners
		testListeners(t, p1, p2)
		p1.Shutdown()
		p2.Shutdown()
	}
}

// testPeer tests the given peer's flags and stats
func testPeer(t *testing.T, p *peer.Peer, s peerStats) {
	if p.ID() != s.wantID {
		t.Errorf("testPeer: wrong ID - got %v, want %v", p.ID(), s.wantID)
		return
	}

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

	stats := p.StatsSnapshot()

	if stats.ID != s.wantID {
		t.Errorf("testPeer: wrong ID - got %v, want %v", stats.ID, s.wantID)
		return
	}
}

// testListeners tests that custom message listeners are working as expected.
func testListeners(t *testing.T, p1 *peer.Peer, p2 *peer.Peer) {
	tests := []struct {
		handler string
		msg     wire.Message
	}{
		{
			"handleGetAddr",
			wire.NewMsgGetAddr(),
		},
		{
			"handleAddr",
			wire.NewMsgAddr(),
		},
		{
			"handlePing",
			wire.NewMsgPing(42),
		},
		{
			"handlePong",
			wire.NewMsgPong(42),
		},
		{
			"handleAlert",
			wire.NewMsgAlert([]byte("payload"), []byte("signature")),
		},
		{
			"handleMemPool",
			wire.NewMsgMemPool(),
		},
		{
			"handleTx",
			wire.NewMsgTx(),
		},
		{
			"handleBlock",
			wire.NewMsgBlock(wire.NewBlockHeader(&wire.ShaHash{}, &wire.ShaHash{}, 1, 1)),
		},
		{
			"handleInv",
			wire.NewMsgInv(),
		},
		{
			"handleHeaders",
			wire.NewMsgHeaders(),
		},
		{
			"handleNotFound",
			wire.NewMsgNotFound(),
		},
		{
			"handleGetData",
			wire.NewMsgGetData(),
		},
		{
			"handleGetBlocks",
			wire.NewMsgGetBlocks(&wire.ShaHash{}),
		},
		{
			"handleGetHeaders",
			wire.NewMsgGetHeaders(),
		},
		{
			"handleFilterAddMsg",
			wire.NewMsgFilterAdd([]byte{0x01}),
		},
		{
			"handleFilterClearMsg",
			wire.NewMsgFilterClear(),
		},
		{
			"handleFilterLoadMsg",
			wire.NewMsgFilterLoad([]byte{0x01}, 10, 0, wire.BloomUpdateNone),
		},
		// only one version message is allowed
		// only one verack message is allowed
		{
			"handleMsgReject",
			wire.NewMsgReject("block", wire.RejectDuplicate, "dupe block"),
		},
	}

	for i, test := range tests {
		// Chan to make sure the listener is fired
		ok := make(chan struct{})

		// Add listener and use chan to signal when it is called
		switch test.msg.(type) {
		case *wire.MsgGetAddr:
			p1.AddGetAddrMsgListener(test.handler, func(*peer.Peer, *wire.MsgGetAddr) {
				ok <- struct{}{}
			})
		case *wire.MsgAddr:
			p1.AddAddrMsgListener(test.handler, func(*peer.Peer, *wire.MsgAddr) {
				ok <- struct{}{}
			})
		case *wire.MsgPing:
			p1.AddPingMsgListener(test.handler, func(*peer.Peer, *wire.MsgPing) {
				ok <- struct{}{}
			})
		case *wire.MsgPong:
			p1.AddPongMsgListener(test.handler, func(*peer.Peer, *wire.MsgPong) {
				ok <- struct{}{}
			})
		case *wire.MsgAlert:
			p1.AddAlertMsgListener(test.handler, func(*peer.Peer, *wire.MsgAlert) {
				ok <- struct{}{}
			})
		case *wire.MsgMemPool:
			p1.AddMemPoolMsgListener(test.handler, func(*peer.Peer, *wire.MsgMemPool) {
				ok <- struct{}{}
			})
		case *wire.MsgTx:
			p1.AddTxMsgListener(test.handler, func(*peer.Peer, *wire.MsgTx) {
				ok <- struct{}{}
			})
		case *wire.MsgBlock:
			p1.AddBlockMsgListener(test.handler, func(*peer.Peer, *wire.MsgBlock, []byte) {
				ok <- struct{}{}
			})
		case *wire.MsgInv:
			p1.AddInvMsgListener(test.handler, func(*peer.Peer, *wire.MsgInv) {
				ok <- struct{}{}
			})
		case *wire.MsgHeaders:
			p1.AddHeadersMsgListener(test.handler, func(*peer.Peer, *wire.MsgHeaders) {
				ok <- struct{}{}
			})
		case *wire.MsgNotFound:
			p1.AddNotFoundMsgListener(test.handler, func(*peer.Peer, *wire.MsgNotFound) {
				ok <- struct{}{}
			})
		case *wire.MsgGetData:
			p1.AddGetDataMsgListener(test.handler, func(*peer.Peer, *wire.MsgGetData) {
				ok <- struct{}{}
			})
		case *wire.MsgGetBlocks:
			p1.AddGetBlocksMsgListener(test.handler, func(*peer.Peer, *wire.MsgGetBlocks) {
				ok <- struct{}{}
			})
		case *wire.MsgGetHeaders:
			p1.AddGetHeadersMsgListener(test.handler, func(*peer.Peer, *wire.MsgGetHeaders) {
				ok <- struct{}{}
			})
		case *wire.MsgFilterAdd:
			p1.AddFilterAddMsgListener(test.handler, func(*peer.Peer, *wire.MsgFilterAdd) {
				ok <- struct{}{}
			})
		case *wire.MsgFilterClear:
			p1.AddFilterClearMsgListener(test.handler, func(*peer.Peer, *wire.MsgFilterClear) {
				ok <- struct{}{}
			})
		case *wire.MsgFilterLoad:
			p1.AddFilterLoadMsgListener(test.handler, func(*peer.Peer, *wire.MsgFilterLoad) {
				ok <- struct{}{}
			})
		case *wire.MsgVersion:
			p1.AddVersionMsgListener(test.handler, func(*peer.Peer, *wire.MsgVersion) {
				ok <- struct{}{}
			})
		case *wire.MsgVerAck:
			p1.AddVerAckMsgListener(test.handler, func(*peer.Peer, *wire.MsgVerAck) {
				ok <- struct{}{}
			})
		case *wire.MsgReject:
			p1.AddRejectMsgListener(test.handler, func(*peer.Peer, *wire.MsgReject) {
				ok <- struct{}{}
			})
		}

		// Queue the test message
		p2.QueueMessage(test.msg, nil)
		// Timeout in case something goes wrong
		select {
		case <-ok:
			// Should receive ok from the listener
		case <-time.After(time.Second * 1):
			t.Errorf("testListeners #%d: expected handler %s to be called", i, test.handler)
			return
		}

		// Reset listeners
		p1.RemoveGetAddrMsgListener(test.handler)
		p1.RemoveAddrMsgListener(test.handler)
		p1.RemovePingMsgListener(test.handler)
		p1.RemovePongMsgListener(test.handler)
		p1.RemoveAlertMsgListener(test.handler)
		p1.RemoveMemPoolMsgListener(test.handler)
		p1.RemoveTxMsgListener(test.handler)
		p1.RemoveBlockMsgListener(test.handler)
		p1.RemoveInvMsgListener(test.handler)
		p1.RemoveHeadersMsgListener(test.handler)
		p1.RemoveNotFoundMsgListener(test.handler)
		p1.RemoveGetDataMsgListener(test.handler)
		p1.RemoveGetBlocksMsgListener(test.handler)
		p1.RemoveGetHeadersMsgListener(test.handler)
		p1.RemoveFilterAddMsgListener(test.handler)
		p1.RemoveFilterClearMsgListener(test.handler)
		p1.RemoveFilterLoadMsgListener(test.handler)
		p1.RemoveVersionMsgListener(test.handler)
		p1.RemoveVerAckMsgListener(test.handler)
		p1.RemoveRejectMsgListener(test.handler)
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
		BestLocalAddress: addrMgr.GetBestLocalAddress,
		UserAgentName:    "peer",
		UserAgentVersion: "1.0",
		Net:              wire.MainNet,
		Services:         wire.SFNodeNetwork,
	}

	r, w := io.Pipe()
	c := &conn{raddr: "127.0.0.1:8333", Writer: w, Reader: r}

	na, err := addrMgr.HostToNetAddress("127.0.0.1", uint16(8333), peerCfg.Services)
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
	done := make(chan struct{}, 5)
	p.QueueMessage(fakeMsg, done)
	<-done
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
	if p1.LastAnnouncedBlock() != latestBlockSha {
		t.Errorf("LastAnnouncedBlock: wrong block - got %v, want %v",
			p1.LastAnnouncedBlock(), latestBlockSha)
		return
	}

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

// Copyright (c) 2015 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package peer_test

import (
	"io"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/btcsuite/btcd/addrmgr"
	"github.com/btcsuite/btcd/blockchain"
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

var gotHandlers = make(chan string, 11)

var wantHandlers = map[string]struct{}{
	"handleVersionMsg":    struct{}{},
	"handleMemPoolMsg":    struct{}{},
	"handleTxMsg":         struct{}{},
	"handleBlockMsg":      struct{}{},
	"handleInvMsg":        struct{}{},
	"handleHeadersMsg":    struct{}{},
	"handleGetDataMsg":    struct{}{},
	"handleGetBlocksMsg":  struct{}{},
	"handleGetHeadersMsg": struct{}{},
	"handleGetAddrMsg":    struct{}{},
	"handleAddrMsg":       struct{}{},
}

func handleVersionMsg(p *peer.Peer, msg *wire.MsgVersion) {
	p.QueueMessage(wire.NewMsgGetAddr(), nil)
	gotHandlers <- "handleVersionMsg"
}

func handleMemPoolMsg(p *peer.Peer, msg *wire.MsgMemPool) {
	gotHandlers <- "handleMemPoolMsg"
}

func handleTxMsg(p *peer.Peer, msg *wire.MsgTx) {
	gotHandlers <- "handleTxMsg"
}

func handleBlockMsg(p *peer.Peer, msg *wire.MsgBlock, buf []byte) {
	sha, height, _ := newestSha()
	p.UpdateLastAnnouncedBlock(sha)
	p.UpdateLastBlockHeight(height)

	blockSha := msg.BlockSha()
	locator := blockchain.BlockLocator([]*wire.ShaHash{&blockSha})
	err := p.PushGetBlocksMsg(locator, &zeroHash)
	if err != nil {
		p.LogError("Failed to send getblocks message to peer %s: %v",
			p.Addr(), err)
		p.Disconnect()
		return
	}
	gotHandlers <- "handleBlockMsg"
}

func handleInvMsg(p *peer.Peer, msg *wire.MsgInv) {
	gdmsg := wire.NewMsgGetData()
	p.QueueMessage(gdmsg, nil)
	for _, iv := range msg.InvList {
		p.AddKnownInventory(iv)
	}
	gotHandlers <- "handleInvMsg"
}

func handleHeadersMsg(p *peer.Peer, msg *wire.MsgHeaders) {
	locator := blockchain.BlockLocator([]*wire.ShaHash{})
	p.PushGetHeadersMsg(locator, &zeroHash)
	gotHandlers <- "handleHeadersMsg"
}

func handleGetDataMsg(p *peer.Peer, msg *wire.MsgGetData) {
	notFound := wire.NewMsgNotFound()
	p.QueueMessage(notFound, nil)
	gotHandlers <- "handleGetDataMsg"
}

func handleGetBlocksMsg(p *peer.Peer, msg *wire.MsgGetBlocks) {
	invMsg := wire.NewMsgInv()
	p.QueueMessage(invMsg, nil)
	gotHandlers <- "handleGetBlocksMsg"
}

func handleGetHeadersMsg(p *peer.Peer, msg *wire.MsgGetHeaders) {
	headersMsg := wire.NewMsgHeaders()
	p.QueueMessage(headersMsg, nil)
	gotHandlers <- "handleGetHeadersMsg"
}

func handleGetAddrMsg(p *peer.Peer, msg *wire.MsgGetAddr) {
	addrCache := addrMgr.AddressCache()
	err := p.PushAddrMsg(addrCache)
	if err != nil {
		p.LogError("Can't push address message to %s: %v", p, err)
		p.Disconnect()
		return
	}
	gotHandlers <- "handleGetAddrMsg"
}

func handleAddrMsg(p *peer.Peer, msg *wire.MsgAddr) {
	addrMgr.AddAddresses(msg.AddrList, p.NA())
	gotHandlers <- "handleAddrMsg"
}

// registerListeners registers listeners on peer messages to mimic the standard
// bitcoin protocol.
func registerListeners(p *peer.Peer) {
	p.AddVersionMsgListener("handleVersionMsg", handleVersionMsg)
	p.AddMemPoolMsgListener("handleMemPoolMsg", handleMemPoolMsg)
	p.AddTxMsgListener("handleTxMsg", handleTxMsg)
	p.AddBlockMsgListener("handleBlockMsg", handleBlockMsg)
	p.AddInvMsgListener("handleInvMsg", handleInvMsg)
	p.AddHeadersMsgListener("handleHeadersMsg", handleHeadersMsg)
	p.AddGetDataMsgListener("handleGetDataMsg", handleGetDataMsg)
	p.AddGetBlocksMsgListener("handleGetBlocksMsg", handleGetBlocksMsg)
	p.AddGetHeadersMsgListener("handleGetHeadersMsg", handleGetHeadersMsg)
	p.AddGetAddrMsgListener("handleGetAddrMsg", handleGetAddrMsg)
	p.AddAddrMsgListener("handleAddrMsg", handleAddrMsg)
}

// removeListeners removes listeners registered with a peer.
func removeListeners(p *peer.Peer) {
	p.RemoveVersionMsgListener("handleVersionMsg")
	p.RemoveMemPoolMsgListener("handleMemPoolMsg")
	p.RemoveTxMsgListener("handleTxMsg")
	p.RemoveBlockMsgListener("handleBlockMsg")
	p.RemoveInvMsgListener("handleInvMsg")
	p.RemoveHeadersMsgListener("handleHeadersMsg")
	p.RemoveGetDataMsgListener("handleGetDataMsg")
	p.RemoveGetBlocksMsgListener("handleGetBlocksMsg")
	p.RemoveGetHeadersMsgListener("handleGetHeadersMsg")
	p.RemoveGetAddrMsgListener("handleGetAddrMsg")
	p.RemoveAddrMsgListener("handleAddrMsg")
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
	c1, c2 := pipe(
		&conn{raddr: "127.0.0.1:8333"},
		&conn{raddr: "127.0.0.1:8333"},
	)

	p1 := peer.NewInboundPeer(peerCfg, 0, c1)
	registerListeners(p1)
	err := p1.Start()
	if err != nil {
		t.Errorf("Start: error %v", err)
		return
	}

	host, portStr, err := net.SplitHostPort("127.0.0.1:8333")
	if err != nil {
		t.Errorf("SplitHostPort: error %v\n", err)
		return
	}

	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		t.Errorf("ParseUint: error %v\n", err)
		return
	}
	na, err := addrMgr.HostToNetAddress(host, uint16(port), 0)
	if err != nil {
		t.Errorf("HostToNetAddress: error %v\n", err)
		return
	}
	p2 := peer.NewOutboundPeer(peerCfg, 1, na)
	p2.Connect(c2)

	locator := blockchain.BlockLocator([]*wire.ShaHash{})
	p2.PushGetBlocksMsg(locator, &zeroHash)
	p2.PushGetHeadersMsg(locator, &zeroHash)
	p2.PushRejectMsg(wire.CmdBlock, wire.RejectInvalid, "test reject", &zeroHash, false)

	fakeHeader := wire.NewBlockHeader(&zeroHash, &zeroHash, 1, 1)
	msgBlock := wire.NewMsgBlock(fakeHeader)

	// Test protocol messages
	p2.QueueMessage(wire.NewMsgPing(uint64(p1.ID())), nil)
	p2.QueueMessage(wire.NewMsgGetAddr(), nil)
	p2.QueueMessage(msgBlock, nil)
	p2.QueueMessage(wire.NewMsgMemPool(), nil)
	p2.QueueMessage(wire.NewMsgTx(), nil)
	p2.QueueMessage(wire.NewMsgHeaders(), nil)
	p2.QueueMessage(wire.NewMsgGetData(), nil)
	p2.QueueMessage(wire.NewMsgGetBlocks(&zeroHash), nil)
	p2.QueueMessage(wire.NewMsgGetHeaders(), nil)
	p2.QueueMessage(wire.NewMsgAddr(), nil)

	hash, _, err := newestSha()
	if err == nil {
		fakeInvMsg := wire.NewMsgInvSizeHint(1)
		iv := wire.NewInvVect(wire.InvTypeBlock, hash)
		fakeInvMsg.AddInvVect(iv)
		p2.QueueMessage(fakeInvMsg, nil)
	} else {
		t.Errorf("newestSha: error %v\n", err)
		return
	}

	// Test adding block inv
	fakeInv := wire.NewInvVect(wire.InvTypeBlock, &zeroHash)
	p2.QueueInventory(fakeInv)

	removeListeners(p2)

	// Test all handlers are called
out:
	for {
		select {
		case handler := <-gotHandlers:
			delete(wantHandlers, handler)
			if len(wantHandlers) == 0 {
				break out
			}
		default:
		}
	}

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

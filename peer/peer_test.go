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
		Net:              wire.MainNet,
		Services:         0,
	}

	r, w := io.Pipe()
	c := &conn{raddr: "127.0.0.1:8333", Writer: w, Reader: r}

	na := wire.NewNetAddressIPPort(net.IP{127, 0, 0, 1}, uint16(8333), 0)
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

	// Reset NewestBlock to normal Start
	peerCfg.NewestBlock = newestSha
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
	peerCfg.RegressionTest = true
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

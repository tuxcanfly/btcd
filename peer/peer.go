// Copyright (c) 2013-2015 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package peer

import (
	"bytes"
	"container/list"
	"fmt"
	"io"
	prand "math/rand"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/go-socks/socks"
	"github.com/davecgh/go-spew/spew"
)

const (
	// MaxProtocolVersion is the max protocol version the peer supports.
	MaxProtocolVersion = 70002

	// outputBufferSize is the number of elements the output channels use.
	outputBufferSize = 50

	// invTrickleSize is the maximum amount of inventory to send in a single
	// message when trickling inventory to remote peers.
	maxInvTrickleSize = 1000

	// maxKnownInventory is the maximum number of items to keep in the known
	// inventory cache.
	maxKnownInventory = 1000

	// negotiateTimeoutSeconds is the number of seconds of inactivity before
	// we timeout a peer that hasn't completed the initial version
	// negotiation.
	negotiateTimeoutSeconds = 30

	// idleTimeoutMinutes is the number of minutes of inactivity before
	// we time out a peer.
	idleTimeoutMinutes = 5

	// pingTimeoutMinutes is the number of minutes since we last sent a
	// message requiring a reply before we will ping a host.
	pingTimeoutMinutes = 2
)

var (
	// nodeCount is the total number of peer connections made since startup
	// and is used to assign an id to a peer.
	nodeCount int32

	// zeroHash is the zero value hash (all zeros).  It is defined as a
	// convenience.
	zeroHash wire.ShaHash
)

// Config is the struct to hold configuration options useful to Peer.
type Config struct {

	// Callback which returns the newest block details
	NewestBlock ShaFunc

	// BestLocalAddress returns the best local address for a given address.
	BestLocalAddress AddrFunc

	// SOCKS5 proxy (eg. 127.0.0.1:9050) to use for connections.
	Proxy string

	// Whether to use the regression test network.
	RegressionTest bool

	// If non-nil, the callback to be invoked when reading a peer message.
	OnRead func(int, *wire.Message, error)

	// If non-nil, the callback to be invoked when writing a peer message.
	OnWrite func(int, *wire.Message, error)

	// User agent string to be used in peer messages.
	UserAgentName string

	// User agent version to be used in peer messages.
	UserAgentVersion string

	// Network flag to be used.
	Net wire.BitcoinNet

	// Services flag to be advertised in peer messages.
	Services wire.ServiceFlag
}

// minUint32 is a helper function to return the minimum of two uint32s.
// This avoids a math import and the need to cast to floats.
func minUint32(a, b uint32) uint32 {
	if a < b {
		return a
	}
	return b
}

// newNetAddress attempts to extract the IP address and port from the passed
// net.Addr interface and create a bitcoin NetAddress structure using that
// information.
func newNetAddress(addr net.Addr, services wire.ServiceFlag) (*wire.NetAddress, error) {
	// addr will be a net.TCPAddr when not using a proxy.
	if tcpAddr, ok := addr.(*net.TCPAddr); ok {
		ip := tcpAddr.IP
		port := uint16(tcpAddr.Port)
		na := wire.NewNetAddressIPPort(ip, port, services)
		return na, nil
	}

	// addr will be a socks.ProxiedAddr when using a proxy.
	if proxiedAddr, ok := addr.(*socks.ProxiedAddr); ok {
		ip := net.ParseIP(proxiedAddr.Host)
		if ip == nil {
			ip = net.ParseIP("0.0.0.0")
		}
		port := uint16(proxiedAddr.Port)
		na := wire.NewNetAddressIPPort(ip, port, services)
		return na, nil
	}

	// For the most part, addr should be one of the two above cases, but
	// to be safe, fall back to trying to parse the information from the
	// address string as a last resort.
	host, portStr, err := net.SplitHostPort(addr.String())
	if err != nil {
		return nil, err
	}
	ip := net.ParseIP(host)
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return nil, err
	}
	na := wire.NewNetAddressIPPort(ip, uint16(port), services)
	return na, nil
}

// outMsg is used to house a message to be sent along with a channel to signal
// when the message has been sent (or won't be sent due to things such as
// shutdown)
type outMsg struct {
	msg      wire.Message
	doneChan chan struct{}
}

// stats is the collection of stats related to a peer.
type stats struct {
	statsMtx           sync.RWMutex // protects all statistics below here.
	versionKnown       bool
	protocolVersion    uint32
	versionSent        bool
	verAckReceived     bool
	timeOffset         int64
	timeConnected      time.Time
	lastSend           time.Time
	lastRecv           time.Time
	bytesReceived      uint64
	bytesSent          uint64
	startingHeight     int32
	lastBlock          int32
	lastAnnouncedBlock *wire.ShaHash
	lastPingNonce      uint64    // Set to nonce if we have a pending ping.
	lastPingTime       time.Time // Time we sent last ping.
	lastPingMicros     int64     // Time for last ping to return.
}

// StatsSnap is a snapshot of peer stats at at point in time.
type StatsSnap struct {
	ID             int32
	Addr           string
	Services       string
	LastSend       int64
	LastRecv       int64
	BytesSent      uint64
	BytesRecv      uint64
	ConnTime       int64
	TimeOffset     int64
	Version        uint32
	UserAgent      string
	Inbound        bool
	StartingHeight int32
	LastBlock      int32
	LastPingNonce  uint64
	LastPingTime   time.Time
	LastPingMicros int64
}

// ShaFunc is a function which returns a block sha, height and error
// It is used as a callback to get newest block details.
type ShaFunc func() (sha *wire.ShaHash, height int32, err error)

// AddrFunc is a func which takes an address and returns a related address.
type AddrFunc func(remoteAddr *wire.NetAddress) *wire.NetAddress

// NOTE: The overall data flow of a peer is split into 3 goroutines.  Inbound
// messages are read via the inHandler goroutine and generally dispatched to
// their own handler.  For inbound data-related messages such as blocks,
// transactions, and inventory, the data is handled by the corresponding
// message handlers.  The data flow for outbound messages is split into 2
// goroutines, queueHandler and outHandler.  The first, queueHandler, is used
// as a way for external entities to queue messages, by way of the QueueMessage
// function, quickly regardless of whether the peer is currently sending or not.
// It acts as the traffic cop between the external world and the actual
// goroutine which writes to the network socket.

// Peer provides a basic concurrent safe bitcoin peer for handling bitcoin
// communications via the peer-to-peer protocol.  It provides full duplex
// reading and writing, automatic handling of the initial handshake process,
// querying of usage statistics and other information about the remote peer such
// as its address, user agent, and protocol version, output message queueing,
// inventory trickling, and the ability to dynamically register and unregister
// callbacks for handling bitcoin protocol messages.
//
// Outbound messages are typically queued via QueueMessage or QueueInventory.
// QueueMessage is intended for all messages, including responses to data such
// as blocks and transactions.  QueueInventory, on the other hand, is only
// intended for relaying inventory as it employs a trickling mechanism to batch
// the inventory together.  However, some helper functions for pushing messages
// of specific types that typically require common special handling are
// provided as a convenience.
//
// The Add<Foo>Listener and Remove<Foo>Listener family of functions provide the
// ability for the caller to add and remove handlers, respectively, for each of
// the protocol messages the caller is interested in.
type Peer struct {
	btcnet     wire.BitcoinNet
	started    int32
	connected  int32
	disconnect int32 // only to be used atomically
	conn       net.Conn

	addr    string
	cfg     *Config
	inbound bool

	flagsMtx  sync.Mutex // protects the peer flags below
	na        *wire.NetAddress
	id        int32
	userAgent string
	services  wire.ServiceFlag

	knownInventory     *MruInventoryMap
	prevGetBlocksBegin *wire.ShaHash
	prevGetBlocksStop  *wire.ShaHash
	prevGetHdrsBegin   *wire.ShaHash
	prevGetHdrsStop    *wire.ShaHash
	outputQueue        chan outMsg
	sendQueue          chan outMsg
	sendDoneQueue      chan struct{}
	queueWg            sync.WaitGroup // TODO(oga) wg -> single use channel?
	outputInvChan      chan *wire.InvVect
	quit               chan struct{}

	stats

	newestSha ShaFunc
	nonce     uint64

	listenerMtx             sync.Mutex
	getAddrMsgListeners     map[string]func(*Peer, *wire.MsgGetAddr)
	addrMsgListeners        map[string]func(*Peer, *wire.MsgAddr)
	pingMsgListeners        map[string]func(*Peer, *wire.MsgPing)
	pongMsgListeners        map[string]func(*Peer, *wire.MsgPong)
	alertMsgListeners       map[string]func(*Peer, *wire.MsgAlert)
	memPoolMsgListeners     map[string]func(*Peer, *wire.MsgMemPool)
	txMsgListeners          map[string]func(*Peer, *wire.MsgTx)
	blockMsgListeners       map[string]func(*Peer, *wire.MsgBlock, []byte)
	invMsgListeners         map[string]func(*Peer, *wire.MsgInv)
	headersMsgListeners     map[string]func(*Peer, *wire.MsgHeaders)
	notFoundMsgListeners    map[string]func(*Peer, *wire.MsgNotFound)
	getDataMsgListeners     map[string]func(*Peer, *wire.MsgGetData)
	getBlocksMsgListeners   map[string]func(*Peer, *wire.MsgGetBlocks)
	getHeadersMsgListeners  map[string]func(*Peer, *wire.MsgGetHeaders)
	filterAddMsgListeners   map[string]func(*Peer, *wire.MsgFilterAdd)
	filterClearMsgListeners map[string]func(*Peer, *wire.MsgFilterClear)
	filterLoadMsgListeners  map[string]func(*Peer, *wire.MsgFilterLoad)
	versionMsgListeners     map[string]func(*Peer, *wire.MsgVersion)
	verackMsgListeners      map[string]func(*Peer, *wire.MsgVerAck)
	rejectMsgListeners      map[string]func(*Peer, *wire.MsgReject)
}

// String returns the peer's address and directionality as a human-readable
// string.
func (p *Peer) String() string {
	return fmt.Sprintf("%s (%s)", p.addr, directionString(p.inbound))
}

// isKnownInventory returns whether or not the peer is known to have the passed
// inventory.  It is safe for concurrent access.
func (p *Peer) isKnownInventory(invVect *wire.InvVect) bool {
	if p.knownInventory.Exists(invVect) {
		return true
	}
	return false
}

// UpdateLastBlockHeight updates the last known block for the peer. It is safe
// for concurrent access.
func (p *Peer) UpdateLastBlockHeight(newHeight int32) {
	p.statsMtx.Lock()
	defer p.statsMtx.Unlock()

	log.Tracef("Updating last block height of peer %v from %v to %v",
		p.addr, p.lastBlock, newHeight)
	p.lastBlock = int32(newHeight)
}

// UpdateLastAnnouncedBlock updates meta-data about the last block sha this
// peer is known to have announced. It is safe for concurrent access.
func (p *Peer) UpdateLastAnnouncedBlock(blkSha *wire.ShaHash) {
	p.statsMtx.Lock()
	defer p.statsMtx.Unlock()

	log.Tracef("Updating last blk for peer %v, %v", p.addr, blkSha)
	p.lastAnnouncedBlock = blkSha
}

// AddKnownInventory adds the passed inventory to the cache of known inventory
// for the peer.  It is safe for concurrent access.
func (p *Peer) AddKnownInventory(invVect *wire.InvVect) {
	p.knownInventory.Add(invVect)
}

// StatsSnapshot returns a snapshot of the current peer statistics.
func (p *Peer) StatsSnapshot() *StatsSnap {
	p.statsMtx.RLock()
	defer p.statsMtx.RUnlock()

	p.flagsMtx.Lock()
	id := p.id
	addr := p.addr
	userAgent := p.userAgent
	services := p.services
	p.flagsMtx.Unlock()

	// Get a copy of all relevant flags and stats.
	return &StatsSnap{
		ID:             id,
		Addr:           addr,
		UserAgent:      userAgent,
		Services:       fmt.Sprintf("%08d", services),
		LastSend:       p.lastSend.Unix(),
		LastRecv:       p.lastRecv.Unix(),
		BytesSent:      p.bytesSent,
		BytesRecv:      p.bytesReceived,
		ConnTime:       p.timeConnected.Unix(),
		TimeOffset:     p.timeOffset,
		Version:        p.protocolVersion,
		Inbound:        p.inbound,
		StartingHeight: p.startingHeight,
		LastBlock:      p.lastBlock,
		LastPingNonce:  p.lastPingNonce,
		LastPingMicros: p.lastPingMicros,
		LastPingTime:   p.lastPingTime,
	}
}

// ID returns the peer id.
func (p *Peer) ID() int32 {
	p.flagsMtx.Lock()
	defer p.flagsMtx.Unlock()

	return p.id
}

// NA returns the peer network address.
func (p *Peer) NA() *wire.NetAddress {
	p.flagsMtx.Lock()
	defer p.flagsMtx.Unlock()

	return p.na
}

// Addr returns the peer address.
// The address doesn't change after initialization, therefore it is not
// protected by a mutex.
func (p *Peer) Addr() string {
	return p.addr
}

// Inbound returns whether the peer is inbound.
func (p *Peer) Inbound() bool {
	return p.inbound
}

// Services returns the services flag of the peer.
func (p *Peer) Services() wire.ServiceFlag {
	p.flagsMtx.Lock()
	defer p.flagsMtx.Unlock()

	return p.services

}

// UserAgent returns the user agent of the peer.
func (p *Peer) UserAgent() string {
	p.flagsMtx.Lock()
	defer p.flagsMtx.Unlock()

	return p.userAgent
}

// LastAnnouncedBlock returns the last announced block of the peer.
func (p *Peer) LastAnnouncedBlock() *wire.ShaHash {
	p.statsMtx.RLock()
	defer p.statsMtx.RUnlock()

	return p.lastAnnouncedBlock
}

// LastPingNonce returns the last ping nonce of the peer.
func (p *Peer) LastPingNonce() uint64 {
	p.statsMtx.RLock()
	defer p.statsMtx.RUnlock()

	return p.lastPingNonce
}

// LastPingTime returns the last ping time of the peer.
func (p *Peer) LastPingTime() time.Time {
	p.statsMtx.RLock()
	defer p.statsMtx.RUnlock()

	return p.lastPingTime
}

// LastPingMicros returns the last ping micros of the peer.
func (p *Peer) LastPingMicros() int64 {
	p.statsMtx.RLock()
	defer p.statsMtx.RUnlock()

	return p.lastPingMicros
}

// VersionKnown returns the whether or not the version of a peer is known
// locally.  It is safe for concurrent access.
func (p *Peer) VersionKnown() bool {
	p.statsMtx.RLock()
	defer p.statsMtx.RUnlock()

	return p.versionKnown
}

// VerAckReceived returns whether or not a verack message was received by the
// peer.  It is safe for concurrent accecss.
func (p *Peer) VerAckReceived() bool {
	p.statsMtx.RLock()
	defer p.statsMtx.RUnlock()

	return p.verAckReceived
}

// ProtocolVersion returns the peer protocol version in a manner that is safe
// for concurrent access.
func (p *Peer) ProtocolVersion() uint32 {
	p.statsMtx.RLock()
	defer p.statsMtx.RUnlock()

	return p.protocolVersion
}

// LastBlock returns the last block of the peer.
func (p *Peer) LastBlock() int32 {
	p.statsMtx.RLock()
	defer p.statsMtx.RUnlock()

	return p.lastBlock
}

// LastSend returns the last send time of the peer.
func (p *Peer) LastSend() time.Time {
	p.statsMtx.RLock()
	defer p.statsMtx.RUnlock()

	return p.lastSend
}

// LastRecv returns the last recv time of the peer.
func (p *Peer) LastRecv() time.Time {
	p.statsMtx.RLock()
	defer p.statsMtx.RUnlock()

	return p.lastRecv
}

// BytesSent returns the bytes sent by the peer.
func (p *Peer) BytesSent() uint64 {
	p.statsMtx.RLock()
	defer p.statsMtx.RUnlock()

	return p.bytesSent
}

// BytesReceived returns the bytes received by the peer.
func (p *Peer) BytesReceived() uint64 {
	p.statsMtx.RLock()
	defer p.statsMtx.RUnlock()

	return p.bytesReceived
}

// TimeConnected returns the time at which the peer connected.
func (p *Peer) TimeConnected() time.Time {
	p.statsMtx.RLock()
	defer p.statsMtx.RUnlock()

	return p.timeConnected
}

// TimeOffset returns the time offset from the peer.
func (p *Peer) TimeOffset() int64 {
	p.statsMtx.RLock()
	defer p.statsMtx.RUnlock()

	return p.timeOffset
}

// StartingHeight returns the starting height of the peer.
func (p *Peer) StartingHeight() int32 {
	p.statsMtx.RLock()
	defer p.statsMtx.RUnlock()

	return p.startingHeight
}

// pushVersionMsg sends a version message to the connected peer using the
// current state.
func (p *Peer) pushVersionMsg() error {
	_, blockNum, err := p.newestSha()
	if err != nil {
		return err
	}

	theirNa := p.na

	// If we are behind a proxy and the connection comes from the proxy then
	// we return an unroutable address as their address. This is to prevent
	// leaking the tor proxy address.
	if p.cfg.Proxy != "" {
		proxyaddress, _, err := net.SplitHostPort(p.cfg.Proxy)
		// invalid proxy means poorly configured, be on the safe side.
		if err != nil || p.na.IP.String() == proxyaddress {
			theirNa = &wire.NetAddress{
				Timestamp: time.Now(),
				IP:        net.IP([]byte{0, 0, 0, 0}),
			}
		}
	}

	// Version message.
	msg := wire.NewMsgVersion(
		p.cfg.BestLocalAddress(p.na), theirNa, p.nonce, int32(blockNum))
	msg.AddUserAgent(p.cfg.UserAgentName, p.cfg.UserAgentVersion)

	// XXX: bitcoind appears to always enable the full node services flag
	// of the remote peer netaddress field in the version message regardless
	// of whether it knows it supports it or not.  Also, bitcoind sets
	// the services field of the local peer to 0 regardless of support.
	//
	// Realistically, this should be set as follows:
	// - For outgoing connections:
	//    - Set the local netaddress services to what the local peer
	//      actually supports
	//    - Set the remote netaddress services to 0 to indicate no services
	//      as they are still unknown
	// - For incoming connections:
	//    - Set the local netaddress services to what the local peer
	//      actually supports
	//    - Set the remote netaddress services to the what was advertised by
	//      by the remote peer in its version message
	msg.AddrYou.Services = wire.SFNodeNetwork

	// Advertise the services flag
	msg.Services = p.Services()

	// Advertise our max supported protocol version.
	msg.ProtocolVersion = MaxProtocolVersion

	p.QueueMessage(msg, nil)
	return nil
}

// PushGetBlocksMsg sends a getblocks message for the provided block locator
// and stop hash.  It will ignore back-to-back duplicate requests.
func (p *Peer) PushGetBlocksMsg(locator blockchain.BlockLocator, stopHash *wire.ShaHash) error {
	// Extract the begin hash from the block locator, if one was specified,
	// to use for filtering duplicate getblocks requests.
	var beginHash *wire.ShaHash
	if len(locator) > 0 {
		beginHash = locator[0]
	}

	// Filter duplicate getblocks requests.
	if p.prevGetBlocksStop != nil && p.prevGetBlocksBegin != nil &&
		beginHash != nil && stopHash.IsEqual(p.prevGetBlocksStop) &&
		beginHash.IsEqual(p.prevGetBlocksBegin) {

		log.Tracef("Filtering duplicate [getblocks] with begin "+
			"hash %v, stop hash %v", beginHash, stopHash)
		return nil
	}

	// Construct the getblocks request and queue it to be sent.
	msg := wire.NewMsgGetBlocks(stopHash)
	for _, hash := range locator {
		err := msg.AddBlockLocatorHash(hash)
		if err != nil {
			return err
		}
	}
	p.QueueMessage(msg, nil)

	// Update the previous getblocks request information for filtering
	// duplicates.
	p.prevGetBlocksBegin = beginHash
	p.prevGetBlocksStop = stopHash
	return nil
}

// PushGetHeadersMsg sends a getblocks message for the provided block locator
// and stop hash.  It will ignore back-to-back duplicate requests.
func (p *Peer) PushGetHeadersMsg(locator blockchain.BlockLocator, stopHash *wire.ShaHash) error {
	// Extract the begin hash from the block locator, if one was specified,
	// to use for filtering duplicate getheaders requests.
	var beginHash *wire.ShaHash
	if len(locator) > 0 {
		beginHash = locator[0]
	}

	// Filter duplicate getheaders requests.
	if p.prevGetHdrsStop != nil && p.prevGetHdrsBegin != nil &&
		beginHash != nil && stopHash.IsEqual(p.prevGetHdrsStop) &&
		beginHash.IsEqual(p.prevGetHdrsBegin) {

		log.Tracef("Filtering duplicate [getheaders] with begin "+
			"hash %v", beginHash)
		return nil
	}

	// Construct the getheaders request and queue it to be sent.
	msg := wire.NewMsgGetHeaders()
	msg.HashStop = *stopHash
	for _, hash := range locator {
		err := msg.AddBlockLocatorHash(hash)
		if err != nil {
			return err
		}
	}
	p.QueueMessage(msg, nil)

	// Update the previous getheaders request information for filtering
	// duplicates.
	p.prevGetHdrsBegin = beginHash
	p.prevGetHdrsStop = stopHash
	return nil
}

// PushRejectMsg sends a reject message for the provided command, reject code,
// reject reason, and hash.  The hash will only be used when the command is a tx
// or block and should be nil in other cases.  The wait parameter will cause the
// function to block until the reject message has actually been sent.
func (p *Peer) PushRejectMsg(command string, code wire.RejectCode, reason string, hash *wire.ShaHash, wait bool) {
	// Don't bother sending the reject message if the protocol version
	// is too low.
	if p.VersionKnown() && p.ProtocolVersion() < wire.RejectVersion {
		return
	}

	msg := wire.NewMsgReject(command, code, reason)
	if command == wire.CmdTx || command == wire.CmdBlock {
		if hash == nil {
			log.Warnf("Sending a reject message for command "+
				"type %v which should have specified a hash "+
				"but does not", command)
			hash = &zeroHash
		}
		msg.Hash = *hash
	}

	// Send the message without waiting if the caller has not requested it.
	if !wait {
		p.QueueMessage(msg, nil)
		return
	}

	// Send the message and block until it has been sent before returning.
	doneChan := make(chan struct{}, 1)
	p.QueueMessage(msg, doneChan)
	<-doneChan
}

// handleVersionMsg is invoked when a peer receives a version bitcoin message
// and is used to negotiate the protocol version details as well as kick start
// the communications.
func (p *Peer) handleVersionMsg(msg *wire.MsgVersion) {
	// Detect self connections.
	if msg.Nonce == p.nonce {
		log.Debugf("Disconnecting peer connected to self %s", p)
		p.Disconnect()
		return
	}

	// Notify and disconnect clients that have a protocol version that is
	// too old.
	if msg.ProtocolVersion < int32(wire.MultipleAddressVersion) {
		// Send a reject message indicating the protocol version is
		// obsolete and wait for the message to be sent before
		// disconnecting.
		reason := fmt.Sprintf("protocol version must be %d or greater",
			wire.MultipleAddressVersion)
		p.PushRejectMsg(msg.Command(), wire.RejectObsolete, reason,
			nil, true)
		p.Disconnect()
		return
	}

	// Limit to one version message per peer.
	// No read lock is necessary because versionKnown is not written to in any
	// other goroutine
	if p.versionKnown {
		p.LogError("Only one version message per peer is allowed %s.",
			p)

		// Send an reject message indicating the version message was
		// incorrectly sent twice and wait for the message to be sent
		// before disconnecting.
		p.PushRejectMsg(msg.Command(), wire.RejectDuplicate,
			"duplicate version message", nil, true)

		p.Disconnect()
		return
	}

	// Updating a bunch of stats.
	p.statsMtx.Lock()
	// Negotiate the protocol version.
	p.protocolVersion = minUint32(p.protocolVersion, uint32(msg.ProtocolVersion))
	p.versionKnown = true
	log.Debugf("Negotiated protocol version %d for peer %s",
		p.protocolVersion, p)
	p.lastBlock = msg.LastBlock
	p.startingHeight = msg.LastBlock
	// Set the peer's time offset.
	p.timeOffset = msg.Timestamp.Unix() - time.Now().Unix()
	p.statsMtx.Unlock()

	// Update peer flags
	p.flagsMtx.Lock()
	// Set the peer's ID.
	p.id = atomic.AddInt32(&nodeCount, 1)
	// Set the supported services for the peer to what the remote peer
	// advertised.
	p.services = msg.Services
	// Set the remote peer's user agent.
	p.userAgent = msg.UserAgent
	p.flagsMtx.Unlock()

	// Inbound connections.
	if p.inbound {
		// Set up a NetAddress for the peer to be used with AddrManager.
		// We only do this inbound because outbound set this up
		// at connection time and no point recomputing.
		na, err := newNetAddress(p.conn.RemoteAddr(), p.services)
		if err != nil {
			p.LogError("Can't get remote address: %v", err)
			p.Disconnect()
			return
		}
		p.na = na

		// Send version.
		err = p.pushVersionMsg()
		if err != nil {
			p.LogError("Can't send version message to %s: %v",
				p, err)
			p.Disconnect()
			return
		}
	}

	// Send verack.
	p.QueueMessage(wire.NewMsgVerAck(), nil)

	// TODO: Relay alerts.
}

// AddVersionMsgListener adds a listener which is invoked when a peer receives
// a version bitcoin message.
func (p *Peer) AddVersionMsgListener(key string, listener func(p *Peer, msg *wire.MsgVersion)) {
	p.listenerMtx.Lock()
	defer p.listenerMtx.Unlock()

	p.versionMsgListeners[key] = listener
}

// RemoveVersionMsgListener removes the version message listener with the given
// key.
func (p *Peer) RemoveVersionMsgListener(key string) {
	p.listenerMtx.Lock()
	defer p.listenerMtx.Unlock()

	delete(p.versionMsgListeners, key)
}

// AddVerAckMsgListener adds a listener which is invoked when a peer receives
// a verack bitcoin message.
func (p *Peer) AddVerAckMsgListener(key string, listener func(p *Peer, msg *wire.MsgVerAck)) {
	p.listenerMtx.Lock()
	defer p.listenerMtx.Unlock()

	p.verackMsgListeners[key] = listener
}

// RemoveVerAckMsgListener removes the verack message listener with the given
// key.
func (p *Peer) RemoveVerAckMsgListener(key string) {
	p.listenerMtx.Lock()
	defer p.listenerMtx.Unlock()

	delete(p.verackMsgListeners, key)
}

// AddGetAddrMsgListener adds a listener which is invoked when a peer receives
// a getaddr bitcoin message.
func (p *Peer) AddGetAddrMsgListener(key string, listener func(p *Peer, msg *wire.MsgGetAddr)) {
	p.listenerMtx.Lock()
	defer p.listenerMtx.Unlock()

	p.getAddrMsgListeners[key] = listener
}

// RemoveGetAddrMsgListener removes the getaddr message listener with the given
// key.
func (p *Peer) RemoveGetAddrMsgListener(key string) {
	p.listenerMtx.Lock()
	defer p.listenerMtx.Unlock()

	delete(p.getAddrMsgListeners, key)
}

// AddAddrMsgListener adds a listener which is invoked when a peer receives
// a addr bitcoin message.
func (p *Peer) AddAddrMsgListener(key string, listener func(p *Peer, msg *wire.MsgAddr)) {
	p.listenerMtx.Lock()
	defer p.listenerMtx.Unlock()

	p.addrMsgListeners[key] = listener
}

// RemoveAddrMsgListener removes the addr message listener with the given
// key.
func (p *Peer) RemoveAddrMsgListener(key string) {
	p.listenerMtx.Lock()
	defer p.listenerMtx.Unlock()

	delete(p.addrMsgListeners, key)
}

// AddPingMsgListener adds a listener which is invoked when a peer receives
// a ping bitcoin message.
func (p *Peer) AddPingMsgListener(key string, listener func(p *Peer, msg *wire.MsgPing)) {
	p.listenerMtx.Lock()
	defer p.listenerMtx.Unlock()

	p.pingMsgListeners[key] = listener
}

// RemovePingMsgListener removes the ping message listener with the given
// key.
func (p *Peer) RemovePingMsgListener(key string) {
	p.listenerMtx.Lock()
	defer p.listenerMtx.Unlock()

	delete(p.pingMsgListeners, key)
}

// AddPongMsgListener adds a listener which is invoked when a peer receives
// a pong bitcoin message.
func (p *Peer) AddPongMsgListener(key string, listener func(p *Peer, msg *wire.MsgPong)) {
	p.listenerMtx.Lock()
	defer p.listenerMtx.Unlock()

	p.pongMsgListeners[key] = listener
}

// RemovePongMsgListener removes the pong message listener with the given
// key.
func (p *Peer) RemovePongMsgListener(key string) {
	p.listenerMtx.Lock()
	defer p.listenerMtx.Unlock()

	delete(p.pongMsgListeners, key)
}

// AddAlertMsgListener adds a listener which is invoked when a peer receives
// a alert bitcoin message.
func (p *Peer) AddAlertMsgListener(key string, listener func(p *Peer, msg *wire.MsgAlert)) {
	p.listenerMtx.Lock()
	defer p.listenerMtx.Unlock()

	p.alertMsgListeners[key] = listener
}

// RemoveAlertMsgListener removes the alert message listener with the given
// key.
func (p *Peer) RemoveAlertMsgListener(key string) {
	p.listenerMtx.Lock()
	defer p.listenerMtx.Unlock()

	delete(p.alertMsgListeners, key)
}

// AddMemPoolMsgListener adds a listener which is invoked when a peer receives
// a mempool bitcoin message.
func (p *Peer) AddMemPoolMsgListener(key string, listener func(p *Peer, msg *wire.MsgMemPool)) {
	p.listenerMtx.Lock()
	defer p.listenerMtx.Unlock()

	p.memPoolMsgListeners[key] = listener
}

// RemoveMemPoolMsgListener removes the mempool message listener with the given
// key.
func (p *Peer) RemoveMemPoolMsgListener(key string) {
	p.listenerMtx.Lock()
	defer p.listenerMtx.Unlock()

	delete(p.memPoolMsgListeners, key)
}

// AddTxMsgListener adds a listener which is invoked when a peer receives a tx
// bitcoin message .
func (p *Peer) AddTxMsgListener(key string, listener func(p *Peer, msg *wire.MsgTx)) {
	p.listenerMtx.Lock()
	defer p.listenerMtx.Unlock()

	p.txMsgListeners[key] = listener
}

// RemoveTxMsgListener removes the tx message listener with the given key.
func (p *Peer) RemoveTxMsgListener(key string) {
	p.listenerMtx.Lock()
	defer p.listenerMtx.Unlock()

	delete(p.txMsgListeners, key)
}

// AddBlockMsgListener adds a listener which is invoked when a peer receives a
// block bitcoin message .
func (p *Peer) AddBlockMsgListener(key string, listener func(p *Peer, msg *wire.MsgBlock, buf []byte)) {
	p.listenerMtx.Lock()
	defer p.listenerMtx.Unlock()

	p.blockMsgListeners[key] = listener
}

// RemoveBlockMsgListener removes the block message listener with the given key.
func (p *Peer) RemoveBlockMsgListener(key string) {
	p.listenerMtx.Lock()
	defer p.listenerMtx.Unlock()

	delete(p.blockMsgListeners, key)
}

// AddInvMsgListener adds a listener which is invoked when a peer receives a
// inv bitcoin message .
func (p *Peer) AddInvMsgListener(key string, listener func(p *Peer, msg *wire.MsgInv)) {
	p.listenerMtx.Lock()
	defer p.listenerMtx.Unlock()

	p.invMsgListeners[key] = listener
}

// RemoveInvMsgListener removes the inv message listener with the given key.
func (p *Peer) RemoveInvMsgListener(key string) {
	p.listenerMtx.Lock()
	defer p.listenerMtx.Unlock()

	delete(p.invMsgListeners, key)
}

// AddHeadersMsgListener adds a listener which is invoked when a peer receives
// a headers bitcoin message .
func (p *Peer) AddHeadersMsgListener(key string, listener func(p *Peer, msg *wire.MsgHeaders)) {
	p.listenerMtx.Lock()
	defer p.listenerMtx.Unlock()

	p.headersMsgListeners[key] = listener
}

// RemoveHeadersMsgListener removes the headers message listener with the given
// key.
func (p *Peer) RemoveHeadersMsgListener(key string) {
	p.listenerMtx.Lock()
	defer p.listenerMtx.Unlock()

	delete(p.headersMsgListeners, key)
}

// AddNotFoundMsgListener adds a listener which is invoked when a peer receives
// a not found bitcoin message .
func (p *Peer) AddNotFoundMsgListener(key string, listener func(p *Peer, msg *wire.MsgNotFound)) {
	p.listenerMtx.Lock()
	defer p.listenerMtx.Unlock()

	p.notFoundMsgListeners[key] = listener
}

// RemoveNotFoundMsgListener removes the not found message listener with the given
// key.
func (p *Peer) RemoveNotFoundMsgListener(key string) {
	p.listenerMtx.Lock()
	defer p.listenerMtx.Unlock()

	delete(p.notFoundMsgListeners, key)
}

// AddGetDataMsgListener adds a listener which is invoked when a peer receives
// a getdata bitcoin message .
func (p *Peer) AddGetDataMsgListener(key string, listener func(p *Peer, msg *wire.MsgGetData)) {
	p.listenerMtx.Lock()
	defer p.listenerMtx.Unlock()

	p.getDataMsgListeners[key] = listener
}

// RemoveGetDataMsgListener removes the getdata message listener with the given
// key.
func (p *Peer) RemoveGetDataMsgListener(key string) {
	p.listenerMtx.Lock()
	defer p.listenerMtx.Unlock()

	delete(p.getDataMsgListeners, key)
}

// AddGetBlocksMsgListener adds a listener which is invoked when a peer receives
// a getblocks bitcoin message .
func (p *Peer) AddGetBlocksMsgListener(key string, listener func(p *Peer, msg *wire.MsgGetBlocks)) {
	p.listenerMtx.Lock()
	defer p.listenerMtx.Unlock()

	p.getBlocksMsgListeners[key] = listener
}

// RemoveGetBlocksMsgListener removes the getblocks message listener with the given
// key.
func (p *Peer) RemoveGetBlocksMsgListener(key string) {
	p.listenerMtx.Lock()
	defer p.listenerMtx.Unlock()

	delete(p.getBlocksMsgListeners, key)
}

// AddGetHeadersMsgListener adds a listener which is invoked when a peer receives
// a getheaders bitcoin message .
func (p *Peer) AddGetHeadersMsgListener(key string, listener func(p *Peer, msg *wire.MsgGetHeaders)) {
	p.listenerMtx.Lock()
	defer p.listenerMtx.Unlock()

	p.getHeadersMsgListeners[key] = listener
}

// RemoveGetHeadersMsgListener removes the getheaders message listener with the given
// key.
func (p *Peer) RemoveGetHeadersMsgListener(key string) {
	p.listenerMtx.Lock()
	defer p.listenerMtx.Unlock()

	delete(p.getHeadersMsgListeners, key)
}

// AddFilterAddMsgListener adds a listener which is invoked when a peer
// receives a filteradd bitcoin message .
func (p *Peer) AddFilterAddMsgListener(key string, listener func(p *Peer, msg *wire.MsgFilterAdd)) {
	p.listenerMtx.Lock()
	defer p.listenerMtx.Unlock()

	p.filterAddMsgListeners[key] = listener
}

// RemoveFilterAddMsgListener removes the filteradd message listener with the
// given key.
func (p *Peer) RemoveFilterAddMsgListener(key string) {
	p.listenerMtx.Lock()
	defer p.listenerMtx.Unlock()

	delete(p.filterAddMsgListeners, key)
}

// AddFilterClearMsgListener adds a listener which is invoked when a peer
// receives a filterclear bitcoin message .
func (p *Peer) AddFilterClearMsgListener(key string, listener func(p *Peer, msg *wire.MsgFilterClear)) {
	p.listenerMtx.Lock()
	defer p.listenerMtx.Unlock()

	p.filterClearMsgListeners[key] = listener
}

// RemoveFilterClearMsgListener removes the filterclear message listener with the
// given key.
func (p *Peer) RemoveFilterClearMsgListener(key string) {
	p.listenerMtx.Lock()
	defer p.listenerMtx.Unlock()

	delete(p.filterClearMsgListeners, key)
}

// AddFilterLoadMsgListener adds a listener which is invoked when a peer
// receives a filterload bitcoin message .
func (p *Peer) AddFilterLoadMsgListener(key string, listener func(p *Peer, msg *wire.MsgFilterLoad)) {
	p.listenerMtx.Lock()
	defer p.listenerMtx.Unlock()

	p.filterLoadMsgListeners[key] = listener
}

// RemoveFilterLoadMsgListener removes the filterload message listener with the
// given key.
func (p *Peer) RemoveFilterLoadMsgListener(key string) {
	p.listenerMtx.Lock()
	defer p.listenerMtx.Unlock()

	delete(p.filterLoadMsgListeners, key)
}

// AddRejectMsgListener adds a listener which is invoked when a peer receives
// a reject bitcoin message.
func (p *Peer) AddRejectMsgListener(key string, listener func(p *Peer, msg *wire.MsgReject)) {
	p.listenerMtx.Lock()
	defer p.listenerMtx.Unlock()

	p.rejectMsgListeners[key] = listener
}

// RemoveRejectMsgListener removes the reject message listener with the given
// key.
func (p *Peer) RemoveRejectMsgListener(key string) {
	p.listenerMtx.Lock()
	defer p.listenerMtx.Unlock()

	delete(p.rejectMsgListeners, key)
}

// PushAddrMsg sends one, or more, addr message(s) to the connected peer using
// the provided addresses.
func (p *Peer) PushAddrMsg(addresses []*wire.NetAddress) error {
	// Nothing to send.
	if len(addresses) == 0 {
		return nil
	}

	r := prand.New(prand.NewSource(time.Now().UnixNano()))
	numAdded := 0
	msg := wire.NewMsgAddr()
	for _, na := range addresses {
		// If the maxAddrs limit has been reached, randomize the list
		// with the remaining addresses.
		if numAdded == wire.MaxAddrPerMsg {
			msg.AddrList[r.Intn(wire.MaxAddrPerMsg)] = na
			continue
		}

		// Add the address to the message.
		err := msg.AddAddress(na)
		if err != nil {
			return err
		}
		numAdded++
	}
	if numAdded > 0 {
		p.QueueMessage(msg, nil)
	}
	return nil
}

// handlePingMsg is invoked when a peer receives a ping bitcoin message.  For
// recent clients (protocol version > BIP0031Version), it replies with a pong
// message.  For older clients, it does nothing and anything other than failure
// is considered a successful ping.
func (p *Peer) handlePingMsg(msg *wire.MsgPing) {
	// Only Reply with pong is message comes from a new enough client.
	if p.ProtocolVersion() > wire.BIP0031Version {
		// Include nonce from ping so pong can be identified.
		p.QueueMessage(wire.NewMsgPong(msg.Nonce), nil)
	}
}

// handlePongMsg is invoked when a peer received a pong bitcoin message.
// recent clients (protocol version > BIP0031Version), and if we had send a ping
// previosuly we update our ping time statistics. If the client is too old or
// we had not send a ping we ignore it.
func (p *Peer) handlePongMsg(msg *wire.MsgPong) {
	p.statsMtx.Lock()
	defer p.statsMtx.Unlock()

	// Arguably we could use a buffered channel here sending data
	// in a fifo manner whenever we send a ping, or a list keeping track of
	// the times of each ping. For now we just make a best effort and
	// only record stats if it was for the last ping sent. Any preceding
	// and overlapping pings will be ignored. It is unlikely to occur
	// without large usage of the ping rpc call since we ping
	// infrequently enough that if they overlap we would have timed out
	// the peer.
	if p.protocolVersion > wire.BIP0031Version &&
		p.lastPingNonce != 0 && msg.Nonce == p.lastPingNonce {
		p.lastPingMicros = time.Now().Sub(p.lastPingTime).Nanoseconds()
		p.lastPingMicros /= 1000 // convert to usec.
		p.lastPingNonce = 0
	}
}

// readMessage reads the next bitcoin message from the peer with logging.
func (p *Peer) readMessage() (wire.Message, []byte, error) {
	n, msg, buf, err := wire.ReadMessageN(p.conn, p.ProtocolVersion(),
		p.btcnet)
	p.statsMtx.Lock()
	p.bytesReceived += uint64(n)
	p.statsMtx.Unlock()
	if p.cfg.OnRead != nil {
		p.cfg.OnRead(n, &msg, err)
	}
	if err != nil {
		return nil, nil, err
	}

	// Use closures to log expensive operations so they are only run when
	// the logging level requires it.
	log.Debugf("%v", newLogClosure(func() string {
		// Debug summary of message.
		summary := messageSummary(msg)
		if len(summary) > 0 {
			summary = " (" + summary + ")"
		}
		return fmt.Sprintf("Received %v%s from %s",
			msg.Command(), summary, p)
	}))
	log.Tracef("%v", newLogClosure(func() string {
		return spew.Sdump(msg)
	}))
	log.Tracef("%v", newLogClosure(func() string {
		return spew.Sdump(buf)
	}))

	return msg, buf, nil
}

// writeMessage sends a bitcoin Message to the peer with logging.
func (p *Peer) writeMessage(msg wire.Message) {
	// Don't do anything if we're disconnecting.
	if atomic.LoadInt32(&p.disconnect) != 0 {
		return
	}
	if !p.VersionKnown() {
		switch msg.(type) {
		case *wire.MsgVersion:
			// This is OK.
		case *wire.MsgReject:
			// This is OK.
		default:
			// Drop all messages other than version and reject if
			// the handshake has not already been done.
			return
		}
	}

	// Use closures to log expensive operations so they are only run when
	// the logging level requires it.
	log.Debugf("%v", newLogClosure(func() string {
		// Debug summary of message.
		summary := messageSummary(msg)
		if len(summary) > 0 {
			summary = " (" + summary + ")"
		}
		return fmt.Sprintf("Sending %v%s to %s", msg.Command(),
			summary, p)
	}))
	log.Tracef("%v", newLogClosure(func() string {
		return spew.Sdump(msg)
	}))
	log.Tracef("%v", newLogClosure(func() string {
		var buf bytes.Buffer
		err := wire.WriteMessage(&buf, msg, p.ProtocolVersion(),
			p.btcnet)
		if err != nil {
			return err.Error()
		}
		return spew.Sdump(buf.Bytes())
	}))

	// Write the message to the peer.
	n, err := wire.WriteMessageN(p.conn, msg, p.ProtocolVersion(),
		p.btcnet)
	p.statsMtx.Lock()
	p.bytesSent += uint64(n)
	p.statsMtx.Unlock()
	if p.cfg.OnWrite != nil {
		p.cfg.OnWrite(n, &msg, err)
	}
	if err != nil {
		p.Disconnect()
		p.LogError("Can't send message to %s: %v", p, err)
		return
	}
}

// isAllowedByRegression returns whether or not the passed error is allowed by
// regression tests without disconnecting the peer.  In particular, regression
// tests need to be allowed to send malformed messages without the peer being
// disconnected.
func (p *Peer) isAllowedByRegression(err error) bool {
	// Don't allow the error if it's not specifically a malformed message
	// error.
	if _, ok := err.(*wire.MessageError); !ok {
		return false
	}

	// Don't allow the error if it's not coming from localhost or the
	// hostname can't be determined for some reason.
	host, _, err := net.SplitHostPort(p.addr)
	if err != nil {
		return false
	}

	if host != "127.0.0.1" && host != "localhost" {
		return false
	}

	// Allowed if all checks passed.
	return true
}

// inHandler handles all incoming messages for the peer.  It must be run as a
// goroutine.
func (p *Peer) inHandler() {
	// Peers must complete the initial version negotiation within a shorter
	// timeframe than a general idle timeout.  The timer is then reset below
	// to idleTimeoutMinutes for all future messages.
	idleTimer := time.AfterFunc(negotiateTimeoutSeconds*time.Second, func() {
		if p.VersionKnown() {
			log.Warnf("Peer %s no answer for %d minutes, "+
				"disconnecting", p, idleTimeoutMinutes)
		}
		p.Disconnect()
	})
out:
	for atomic.LoadInt32(&p.disconnect) == 0 {
		rmsg, buf, err := p.readMessage()
		// Stop the timer now, if we go around again we will reset it.
		idleTimer.Stop()
		if err != nil {
			// In order to allow regression tests with malformed
			// messages, don't disconnect the peer when we're in
			// regression test mode and the error is one of the
			// allowed errors.
			if p.cfg.RegressionTest && p.isAllowedByRegression(err) {
				log.Errorf("Allowed regression test "+
					"error from %s: %v", p, err)
				idleTimer.Reset(idleTimeoutMinutes * time.Minute)
				continue
			}

			// Only log the error and possibly send reject message
			// if we're not forcibly disconnecting.
			if atomic.LoadInt32(&p.disconnect) == 0 {
				errMsg := fmt.Sprintf("Can't read message "+
					"from %s: %v", p, err)
				p.LogError(errMsg)

				// Only send the reject message if it's not
				// because the remote client disconnected.
				if err != io.EOF {
					// Push a reject message for the
					// malformed message and wait for the
					// message to be sent before
					// disconnecting.
					//
					// NOTE: Ideally this would include the
					// command in the header if at least
					// that much of the message was valid,
					// but that is not currently exposed by
					// wire, so just used malformed for the
					// command.
					p.PushRejectMsg("malformed",
						wire.RejectMalformed, errMsg,
						nil, true)
				}

			}
			break out
		}
		p.statsMtx.Lock()
		p.lastRecv = time.Now()
		p.statsMtx.Unlock()

		// Ensure version message comes first.
		if vmsg, ok := rmsg.(*wire.MsgVersion); !ok && !p.VersionKnown() {
			errStr := "A version message must precede all others"
			p.LogError(errStr)

			// Push a reject message and wait for the message to be
			// sent before disconnecting.
			p.PushRejectMsg(vmsg.Command(), wire.RejectMalformed,
				errStr, nil, true)
			break out
		}

		// Handle each supported message type.
		switch msg := rmsg.(type) {
		case *wire.MsgVersion:
			p.handleVersionMsg(msg)

			p.listenerMtx.Lock()
			for key, listener := range p.versionMsgListeners {
				log.Tracef("Running %s listener %s", key, p)
				listener(p, msg)
			}
			p.listenerMtx.Unlock()

		case *wire.MsgVerAck:
			p.statsMtx.RLock()
			versionSent := p.versionSent
			p.statsMtx.RUnlock()

			if !versionSent {
				log.Infof("Received 'verack' from peer %v "+
					"before version was sent -- disconnecting", p)
				break out
			}
			// No read lock is necessary because verAckReceived is not written
			// to in any other goroutine
			if p.verAckReceived {
				log.Infof("Already received 'verack' from "+
					"peer %v -- disconnecting", p)
				break out
			}
			p.statsMtx.Lock()
			p.verAckReceived = true
			p.statsMtx.Unlock()

			p.listenerMtx.Lock()
			for key, listener := range p.verackMsgListeners {
				log.Tracef("Running %s listener %s", key, p)
				listener(p, msg)
			}
			p.listenerMtx.Unlock()

		case *wire.MsgGetAddr:
			p.listenerMtx.Lock()
			for key, listener := range p.getAddrMsgListeners {
				log.Tracef("Running %s listener %s", key, p)
				listener(p, msg)
			}
			p.listenerMtx.Unlock()

		case *wire.MsgAddr:
			p.listenerMtx.Lock()
			for key, listener := range p.addrMsgListeners {
				log.Tracef("Running %s listener %s", key, p)
				listener(p, msg)
			}
			p.listenerMtx.Unlock()

		case *wire.MsgPing:
			p.handlePingMsg(msg)
			p.listenerMtx.Lock()
			for key, listener := range p.pingMsgListeners {
				log.Tracef("Running %s listener %s", key, p)
				listener(p, msg)
			}
			p.listenerMtx.Unlock()

		case *wire.MsgPong:
			p.handlePongMsg(msg)
			p.listenerMtx.Lock()
			for key, listener := range p.pongMsgListeners {
				log.Tracef("Running %s listener %s", key, p)
				listener(p, msg)
			}
			p.listenerMtx.Unlock()

		case *wire.MsgAlert:
			// Note: The reference client currently bans peers that send alerts
			// not signed with its key.  We could verify against their key, but
			// since the reference client is currently unwilling to support
			// other implementions' alert messages, we will not relay theirs.
			p.listenerMtx.Lock()
			for key, listener := range p.alertMsgListeners {
				log.Tracef("Running %s listener %s", key, p)
				listener(p, msg)
			}
			p.listenerMtx.Unlock()

		case *wire.MsgMemPool:
			p.listenerMtx.Lock()
			for key, listener := range p.memPoolMsgListeners {
				log.Tracef("Running %s listener %s", key, p)
				listener(p, msg)
			}
			p.listenerMtx.Unlock()

		case *wire.MsgTx:
			p.listenerMtx.Lock()
			for key, listener := range p.txMsgListeners {
				log.Tracef("Running %s listener for %s", key, p)
				listener(p, msg)
			}
			p.listenerMtx.Unlock()

		case *wire.MsgBlock:
			p.listenerMtx.Lock()
			for key, listener := range p.blockMsgListeners {
				log.Tracef("Running %s listener for %s", key, p)
				listener(p, msg, buf)
			}
			p.listenerMtx.Unlock()

		case *wire.MsgInv:
			p.listenerMtx.Lock()
			for key, listener := range p.invMsgListeners {
				log.Tracef("Running %s listener for %s", key, p)
				listener(p, msg)
			}
			p.listenerMtx.Unlock()

		case *wire.MsgHeaders:
			p.listenerMtx.Lock()
			for key, listener := range p.headersMsgListeners {
				log.Tracef("Running %s listener for %s", key, p)
				listener(p, msg)
			}
			p.listenerMtx.Unlock()

		case *wire.MsgNotFound:
			p.listenerMtx.Lock()
			for key, listener := range p.notFoundMsgListeners {
				log.Tracef("Running %s listener for %s", key, p)
				listener(p, msg)
			}
			p.listenerMtx.Unlock()

		case *wire.MsgGetData:
			p.listenerMtx.Lock()
			for key, listener := range p.getDataMsgListeners {
				log.Tracef("Running %s listener for %s", key, p)
				listener(p, msg)
			}
			p.listenerMtx.Unlock()

		case *wire.MsgGetBlocks:
			p.listenerMtx.Lock()
			for key, listener := range p.getBlocksMsgListeners {
				log.Tracef("Running %s listener for %s", key, p)
				listener(p, msg)
			}
			p.listenerMtx.Unlock()

		case *wire.MsgGetHeaders:
			p.listenerMtx.Lock()
			for key, listener := range p.getHeadersMsgListeners {
				log.Tracef("Running %s listener for %s", key, p)
				listener(p, msg)
			}
			p.listenerMtx.Unlock()

		case *wire.MsgFilterAdd:
			p.listenerMtx.Lock()
			for key, listener := range p.filterAddMsgListeners {
				log.Tracef("Running %s listener for %s", key, p)
				listener(p, msg)
			}
			p.listenerMtx.Unlock()

		case *wire.MsgFilterClear:
			p.listenerMtx.Lock()
			for key, listener := range p.filterClearMsgListeners {
				log.Tracef("Running %s listener for %s", key, p)
				listener(p, msg)
			}
			p.listenerMtx.Unlock()

		case *wire.MsgFilterLoad:
			p.listenerMtx.Lock()
			for key, listener := range p.filterLoadMsgListeners {
				log.Tracef("Running %s listener for %s", key, p)
				listener(p, msg)
			}
			p.listenerMtx.Unlock()

		case *wire.MsgReject:
			p.listenerMtx.Lock()
			for key, listener := range p.rejectMsgListeners {
				log.Tracef("Running %s listener for %s", key, p)
				listener(p, msg)
			}
			p.listenerMtx.Unlock()

		default:
			log.Debugf("Received unhandled message of type %v:",
				rmsg.Command())
		}

		// ok we got a message, reset the timer.
		// timer just calls p.Disconnect() after logging.
		idleTimer.Reset(idleTimeoutMinutes * time.Minute)
	}

	idleTimer.Stop()

	// Ensure connection is closed.
	p.Disconnect()

	log.Tracef("Peer input handler done for %s", p)
}

// queueHandler handles the queueing of outgoing data for the peer. This runs
// as a muxer for various sources of input so we can ensure that server and
// peer handlers will not block on us sending a message.
// We then pass the data on to outHandler to be actually written.
func (p *Peer) queueHandler() {
	pendingMsgs := list.New()
	invSendQueue := list.New()
	trickleTicker := time.NewTicker(time.Second * 10)
	defer trickleTicker.Stop()

	// We keep the waiting flag so that we know if we have a message queued
	// to the outHandler or not.  We could use the presence of a head of
	// the list for this but then we have rather racy concerns about whether
	// it has gotten it at cleanup time - and thus who sends on the
	// message's done channel.  To avoid such confusion we keep a different
	// flag and pendingMsgs only contains messages that we have not yet
	// passed to outHandler.
	waiting := false

	// To avoid duplication below.
	queuePacket := func(msg outMsg, list *list.List, waiting bool) bool {
		if !waiting {
			log.Tracef("%s: sending to outHandler", p)
			p.sendQueue <- msg
			log.Tracef("%s: sent to outHandler", p)
		} else {
			list.PushBack(msg)
		}
		// we are always waiting now.
		return true
	}
out:
	for {
		select {
		case msg := <-p.outputQueue:
			waiting = queuePacket(msg, pendingMsgs, waiting)

		// This channel is notified when a message has been sent across
		// the network socket.
		case <-p.sendDoneQueue:
			log.Tracef("%s: acked by outhandler", p)

			// No longer waiting if there are no more messages
			// in the pending messages queue.
			next := pendingMsgs.Front()
			if next == nil {
				waiting = false
				continue
			}

			// Notify the outHandler about the next item to
			// asynchronously send.
			val := pendingMsgs.Remove(next)
			log.Tracef("%s: sending to outHandler", p)
			p.sendQueue <- val.(outMsg)
			log.Tracef("%s: sent to outHandler", p)

		case iv := <-p.outputInvChan:
			// No handshake?  They'll find out soon enough.
			if p.VersionKnown() {
				invSendQueue.PushBack(iv)
			}

		case <-trickleTicker.C:
			// Don't send anything if we're disconnecting or there
			// is no queued inventory.
			// version is known if send queue has any entries.
			if atomic.LoadInt32(&p.disconnect) != 0 ||
				invSendQueue.Len() == 0 {
				continue
			}

			// Create and send as many inv messages as needed to
			// drain the inventory send queue.
			invMsg := wire.NewMsgInvSizeHint(uint(invSendQueue.Len()))
			for e := invSendQueue.Front(); e != nil; e = invSendQueue.Front() {
				iv := invSendQueue.Remove(e).(*wire.InvVect)

				// Don't send inventory that became known after
				// the initial check.
				if p.isKnownInventory(iv) {
					continue
				}

				invMsg.AddInvVect(iv)
				if len(invMsg.InvList) >= maxInvTrickleSize {
					waiting = queuePacket(
						outMsg{msg: invMsg},
						pendingMsgs, waiting)
					invMsg = wire.NewMsgInvSizeHint(uint(invSendQueue.Len()))
				}

				// Add the inventory that is being relayed to
				// the known inventory for the peer.
				p.AddKnownInventory(iv)
			}
			if len(invMsg.InvList) > 0 {
				waiting = queuePacket(outMsg{msg: invMsg},
					pendingMsgs, waiting)
			}

		case <-p.quit:
			break out
		}
	}

	// Drain any wait channels before we go away so we don't leave something
	// waiting for us.
	for e := pendingMsgs.Front(); e != nil; e = pendingMsgs.Front() {
		val := pendingMsgs.Remove(e)
		msg := val.(outMsg)
		if msg.doneChan != nil {
			msg.doneChan <- struct{}{}
		}
	}
cleanup:
	for {
		select {
		case msg := <-p.outputQueue:
			if msg.doneChan != nil {
				msg.doneChan <- struct{}{}
			}
		case <-p.outputInvChan:
			// Just drain channel
		// sendDoneQueue is buffered so doesn't need draining.
		default:
			break cleanup
		}
	}
	p.queueWg.Done()
	log.Tracef("Peer queue handler done for %s", p)
}

// outHandler handles all outgoing messages for the peer.  It must be run as a
// goroutine.  It uses a buffered channel to serialize output messages while
// allowing the sender to continue running asynchronously.
func (p *Peer) outHandler() {
	pingTimer := time.AfterFunc(pingTimeoutMinutes*time.Minute, func() {
		nonce, err := wire.RandomUint64()
		if err != nil {
			log.Errorf("Not sending ping on timeout to %s: %v",
				p, err)
			return
		}
		p.QueueMessage(wire.NewMsgPing(nonce), nil)
	})
out:
	for {
		select {
		case msg := <-p.sendQueue:
			// If the message is one we should get a reply for
			// then reset the timer, we only want to send pings
			// when otherwise we would not receive a reply from
			// the peer. We specifically do not count block or inv
			// messages here since they are not sure of a reply if
			// the inv is of no interest explicitly solicited invs
			// should elicit a reply but we don't track them
			// specially.
			log.Tracef("%s: received from queuehandler", p)
			reset := true
			switch m := msg.msg.(type) {
			case *wire.MsgVersion:
				// should get a verack
				p.statsMtx.Lock()
				p.versionSent = true
				p.statsMtx.Unlock()
			case *wire.MsgGetAddr:
				// should get addresses
			case *wire.MsgPing:
				// expects pong
				// Also set up statistics.
				p.statsMtx.Lock()
				if p.protocolVersion > wire.BIP0031Version {
					p.lastPingNonce = m.Nonce
					p.lastPingTime = time.Now()
				}
				p.statsMtx.Unlock()
			case *wire.MsgMemPool:
				// Should return an inv.
			case *wire.MsgGetData:
				// Should get us block, tx, or not found.
			case *wire.MsgGetHeaders:
				// Should get us headers back.
			default:
				// Not one of the above, no sure reply.
				// We want to ping if nothing else
				// interesting happens.
				reset = false
			}
			if reset {
				pingTimer.Reset(pingTimeoutMinutes * time.Minute)
			}
			p.writeMessage(msg.msg)
			p.statsMtx.Lock()
			p.lastSend = time.Now()
			p.statsMtx.Unlock()
			if msg.doneChan != nil {
				msg.doneChan <- struct{}{}
			}
			log.Tracef("%s: acking queuehandler", p)
			p.sendDoneQueue <- struct{}{}
			log.Tracef("%s: acked queuehandler", p)

		case <-p.quit:
			break out
		}
	}

	pingTimer.Stop()

	p.queueWg.Wait()

	// Drain any wait channels before we go away so we don't leave something
	// waiting for us. We have waited on queueWg and thus we can be sure
	// that we will not miss anything sent on sendQueue.
cleanup:
	for {
		select {
		case msg := <-p.sendQueue:
			if msg.doneChan != nil {
				msg.doneChan <- struct{}{}
			}
			// no need to send on sendDoneQueue since queueHandler
			// has been waited on and already exited.
		default:
			break cleanup
		}
	}
	log.Tracef("Peer output handler done for %s", p)
}

// QueueMessage adds the passed bitcoin message to the peer send queue.  It
// uses a buffered channel to communicate with the output handler goroutine so
// it is automatically rate limited and safe for concurrent access.
func (p *Peer) QueueMessage(msg wire.Message, doneChan chan struct{}) {
	// Avoid risk of deadlock if goroutine already exited. The goroutine
	// we will be sending to hangs around until it knows for a fact that
	// it is marked as disconnected. *then* it drains the channels.
	if !p.Connected() {
		// avoid deadlock...
		if doneChan != nil {
			go func() {
				doneChan <- struct{}{}
			}()
		}
		return
	}
	p.outputQueue <- outMsg{msg: msg, doneChan: doneChan}
}

// QueueInventory adds the passed inventory to the inventory send queue which
// might not be sent right away, rather it is trickled to the peer in batches.
// Inventory that the peer is already known to have is ignored.  It is safe for
// concurrent access.
func (p *Peer) QueueInventory(invVect *wire.InvVect) {
	// Don't add the inventory to the send queue if the peer is
	// already known to have it.
	if p.isKnownInventory(invVect) {
		return
	}

	// Avoid risk of deadlock if goroutine already exited. The goroutine
	// we will be sending to hangs around until it knows for a fact that
	// it is marked as disconnected. *then* it drains the channels.
	if !p.Connected() {
		return
	}

	p.outputInvChan <- invVect
}

// Connected returns whether or not the peer is currently connected.
func (p *Peer) Connected() bool {
	return atomic.LoadInt32(&p.connected) != 0 &&
		atomic.LoadInt32(&p.disconnect) == 0
}

// Disconnect disconnects the peer by closing the connection.  It also sets
// a flag so the impending shutdown can be detected.
func (p *Peer) Disconnect() {
	if atomic.AddInt32(&p.disconnect, 1) != 1 {
		return
	}

	log.Tracef("disconnecting %s", p)
	if atomic.LoadInt32(&p.connected) != 0 {
		p.conn.Close()
	}
	close(p.quit)
}

// Start begins processing input and output messages.  It also sends the initial
// version message for outbound connections to start the negotiation process.
func (p *Peer) Start() error {
	// Already started?
	if atomic.AddInt32(&p.started, 1) != 1 {
		return nil
	}

	log.Tracef("Starting peer %s", p)

	// Send an initial version message if this is an outbound connection.
	if !p.inbound {
		err := p.pushVersionMsg()
		if err != nil {
			p.LogError("Can't send outbound version message %v", err)
			p.Disconnect()
			return err
		}
	}

	// Start processing input and output.
	go p.inHandler()
	// queueWg is kept so that outHandler knows when the queue has exited so
	// it can drain correctly.
	p.queueWg.Add(1)
	go p.queueHandler()
	go p.outHandler()

	return nil
}

// Shutdown gracefully shuts down the peer by disconnecting it.
func (p *Peer) Shutdown() {
	log.Tracef("Shutdown peer %s", p)
	p.Disconnect()
}

// WaitForShutdown waits until the peer is shutdown.
func (p *Peer) WaitForShutdown() {
	<-p.quit
}

// newPeerBase returns a new base bitcoin peer for the provided server and
// inbound flag.  This is used by the NewInboundPeer and NewOutboundPeer
// functions to perform base setup needed by both types of peers.
func newPeerBase(cfg *Config, nonce uint64, inbound bool) *Peer {
	p := Peer{
		btcnet:         cfg.Net,
		inbound:        inbound,
		knownInventory: NewMruInventoryMap(maxKnownInventory),
		outputQueue:    make(chan outMsg, outputBufferSize),
		sendQueue:      make(chan outMsg, 1),   // nonblocking sync
		sendDoneQueue:  make(chan struct{}, 1), // nonblocking sync
		outputInvChan:  make(chan *wire.InvVect, outputBufferSize),
		quit:           make(chan struct{}),
		stats: stats{
			protocolVersion: MaxProtocolVersion,
		},
		newestSha: cfg.NewestBlock,
		nonce:     nonce,
		cfg:       cfg,
		services:  cfg.Services,

		getAddrMsgListeners:     make(map[string]func(*Peer, *wire.MsgGetAddr)),
		addrMsgListeners:        make(map[string]func(*Peer, *wire.MsgAddr)),
		pingMsgListeners:        make(map[string]func(*Peer, *wire.MsgPing)),
		pongMsgListeners:        make(map[string]func(*Peer, *wire.MsgPong)),
		alertMsgListeners:       make(map[string]func(*Peer, *wire.MsgAlert)),
		memPoolMsgListeners:     make(map[string]func(*Peer, *wire.MsgMemPool)),
		txMsgListeners:          make(map[string]func(*Peer, *wire.MsgTx)),
		blockMsgListeners:       make(map[string]func(*Peer, *wire.MsgBlock, []byte)),
		invMsgListeners:         make(map[string]func(*Peer, *wire.MsgInv)),
		headersMsgListeners:     make(map[string]func(*Peer, *wire.MsgHeaders)),
		notFoundMsgListeners:    make(map[string]func(*Peer, *wire.MsgNotFound)),
		getDataMsgListeners:     make(map[string]func(*Peer, *wire.MsgGetData)),
		getBlocksMsgListeners:   make(map[string]func(*Peer, *wire.MsgGetBlocks)),
		getHeadersMsgListeners:  make(map[string]func(*Peer, *wire.MsgGetHeaders)),
		filterAddMsgListeners:   make(map[string]func(*Peer, *wire.MsgFilterAdd)),
		filterClearMsgListeners: make(map[string]func(*Peer, *wire.MsgFilterClear)),
		filterLoadMsgListeners:  make(map[string]func(*Peer, *wire.MsgFilterLoad)),
		versionMsgListeners:     make(map[string]func(*Peer, *wire.MsgVersion)),
		verackMsgListeners:      make(map[string]func(*Peer, *wire.MsgVerAck)),
		rejectMsgListeners:      make(map[string]func(*Peer, *wire.MsgReject)),
	}
	return &p
}

// NewInboundPeer returns a new inbound bitcoin peer. Use Start to begin
// processing incoming and outgoing messages.
func NewInboundPeer(cfg *Config, nonce uint64, conn net.Conn) *Peer {
	p := newPeerBase(cfg, nonce, true)
	p.conn = conn
	p.addr = conn.RemoteAddr().String()
	p.timeConnected = time.Now()
	atomic.AddInt32(&p.connected, 1)
	return p
}

// NewOutboundPeer returns a new outbound bitcoin peer.
func NewOutboundPeer(cfg *Config, nonce uint64, na *wire.NetAddress) *Peer {
	p := newPeerBase(cfg, nonce, false)
	p.na = na
	p.addr = fmt.Sprintf("%v:%v", na.IP, na.Port)
	return p
}

// Connect uses the given conn to connect to the peer.
func (p *Peer) Connect(conn net.Conn) error {
	p.conn = conn
	p.timeConnected = time.Now()

	// Connection was successful so log it and start peer.
	log.Debugf("Connected to %s", p.conn.RemoteAddr())
	atomic.AddInt32(&p.connected, 1)
	return p.Start()
}

// LogError makes sure that we only log errors loudly on user peers.
func (p *Peer) LogError(fmt string, args ...interface{}) {
	log.Errorf(fmt, args...)
}

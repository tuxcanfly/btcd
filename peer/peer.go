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
	MaxProtocolVersion = 70011

	// BlockStallTimeout is the number of seconds we will wait for a
	// "block" response after we send out a "getdata" for an announced
	// block before we deem the peer inactive, and disconnect it.
	BlockStallTimeout = 5 * time.Second

	// outputBufferSize is the number of elements the output channels use.
	outputBufferSize = 50

	// invTrickleSize is the maximum amount of inventory to send in a single
	// message when trickling inventory to remote peers.
	maxInvTrickleSize = 1000

	// maxKnownInventory is the maximum number of items to keep in the known
	// inventory cache.
	maxKnownInventory = 1000

	// pingTimeout is the duration since we last sent a message requiring a
	// reply before we will ping a host.
	pingTimeout = 2 * time.Minute

	// negotiateTimeout is the duration of inactivity before we timeout a peer
	// that hasn't completed the initial version negotiation.
	negotiateTimeout = 30 * time.Second

	// idleTimeout is the duration of inactivity before we time out a peer.
	idleTimeout = 5 * time.Minute

	// trickleTimeout is the duration of the ticker which trickles down the
	// inventory to a peer.
	trickleTimeout = 10 * time.Second
)

var (
	// nodeCount is the total number of peer connections made since startup
	// and is used to assign an id to a peer.
	nodeCount int32

	// zeroHash is the zero value hash (all zeros).  It is defined as a
	// convenience.
	zeroHash wire.ShaHash

	// sentNonces houses the unique nonces that are generated when pushing
	// version messages that are used to detect self connections.
	sentNonces = newMruNonceMap(50)

	// allowSelfConns is only used to allow the tests to bypass the self
	// connection detecting and disconnect logic since they intentionally
	// do so for testing purposes.
	allowSelfConns bool
)

// MessageListeners defines callback function pointers to invoke with
// message listeners.  Since all of the functions are nil by default, all
// listeners are effectively ignored until their handlers are set to a
// concrete callback.
//
// NOTE: Unless otherwise documented, these listeners must NOT directly call any
// blocking calls on the peer instance since the inHandler  goroutine blocks
// until the callback has completed.  Doing so will result in a deadlock
// situation.
type MessageListeners struct {
	// GetAddrListener is invoked when a peer receives a getaddr bitcoin message.
	GetAddrListener func(p *Peer, msg *wire.MsgGetAddr)

	// AddrListener is invoked when a peer receives a addr bitcoin message.
	AddrListener func(p *Peer, msg *wire.MsgAddr)

	// PingListener is invoked when a peer receives a ping bitcoin message.
	PingListener func(p *Peer, msg *wire.MsgPing)

	// PongListener is invoked when a peer receives a pong bitcoin message.
	PongListener func(p *Peer, msg *wire.MsgPong)

	// AlertListener is invoked when a peer receives a alert bitcoin message.
	AlertListener func(p *Peer, msg *wire.MsgAlert)

	// MemPoolListener is invoked when a peer receives a mempool bitcoin message.
	MemPoolListener func(p *Peer, msg *wire.MsgMemPool)

	// TxListener is invoked when a peer receives a tx bitcoin message.
	TxListener func(p *Peer, msg *wire.MsgTx)

	// BlockListener is invoked when a peer receives a block bitcoin message.
	BlockListener func(p *Peer, msg *wire.MsgBlock, buf []byte)

	// InvListener is invoked when a peer receives a inv bitcoin message.
	InvListener func(p *Peer, msg *wire.MsgInv)

	// HeadersListener is invoked when a peer receives a headers bitcoin message.
	HeadersListener func(p *Peer, msg *wire.MsgHeaders)

	// NotFoundListener is invoked when a peer receives a notfound bitcoin message.
	NotFoundListener func(p *Peer, msg *wire.MsgNotFound)

	// GetDataListener is invoked when a peer receives a getdata bitcoin message.
	GetDataListener func(p *Peer, msg *wire.MsgGetData)

	// GetBlocksListener is invoked when a peer receives a getblocks bitcoin message.
	GetBlocksListener func(p *Peer, msg *wire.MsgGetBlocks)

	// GetHeadersListener is invoked when a peer receives a getheaders bitcoin message.
	GetHeadersListener func(p *Peer, msg *wire.MsgGetHeaders)

	// FilterAddListener is invoked when a peer receives a filteradd bitcoin message.
	FilterAddListener func(p *Peer, msg *wire.MsgFilterAdd)

	// FilterClearListener is invoked when a peer receives a filterclear bitcoin message.
	FilterClearListener func(p *Peer, msg *wire.MsgFilterClear)

	// FilterLoadListener is invoked when a peer receives a filterload bitcoin message.
	FilterLoadListener func(p *Peer, msg *wire.MsgFilterLoad)

	// VersionListener is invoked when a peer receives a version bitcoin message.
	VersionListener func(p *Peer, msg *wire.MsgVersion)

	// VerAckListener is invoked when a peer receives a verack bitcoin message.
	VerAckListener func(p *Peer, msg *wire.MsgVerAck)

	// RejectListener is invoked when a peer receives a reject bitcoin message.
	RejectListener func(p *Peer, msg *wire.MsgReject)
}

// Config is the struct to hold configuration options useful to Peer.
type Config struct {
	// Callback functions to be invoked on receiving peer messages.
	Listeners *MessageListeners

	// Callback which returns the newest block details.  This can be nil
	// in which case the peer will report a block height of 0.
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

	// Protocol version to use.
	ProtocolVersion uint32
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

// StatsSnap is a snapshot of peer stats at a point in time.
type StatsSnap struct {
	ID             int32
	Addr           string
	Services       wire.ServiceFlag
	LastSend       time.Time
	LastRecv       time.Time
	BytesSent      uint64
	BytesRecv      uint64
	ConnTime       time.Time
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

	flagsMtx        sync.Mutex // protects the peer flags below
	na              *wire.NetAddress
	id              int32
	userAgent       string
	services        wire.ServiceFlag
	versionKnown    bool
	protocolVersion uint32
	versionSent     bool
	verAckReceived  bool

	knownInventory     *MruInventoryMap
	prevGetBlocksBegin *wire.ShaHash
	prevGetBlocksStop  *wire.ShaHash
	prevGetHdrsBegin   *wire.ShaHash
	prevGetHdrsStop    *wire.ShaHash
	outputQueue        chan outMsg
	sendQueue          chan outMsg
	sendDoneQueue      chan struct{}
	outputInvChan      chan *wire.InvVect
	blockStallActivate chan time.Duration
	blockStallTimer    <-chan time.Time
	blockStallCancel   chan struct{}
	queueQuit          chan struct{}
	quit               chan struct{}

	stats
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

// SetBlockStallTimer activates the block stall timer for this peer. After the
// block stall timeout mode has been activated, the next outgoing "getdata"
// message which requests a block will start the timer. If 'timeout' seconds
// passes before the peer receives a "block" response, then the peer will
// disconnect itself.
func (p *Peer) SetBlockStallTimer(timeout time.Duration) {
	p.blockStallActivate <- timeout
}

// UpdateLastBlockHeight updates the last known block for the peer. It is safe
// for concurrent access.
func (p *Peer) UpdateLastBlockHeight(newHeight int32) {
	p.statsMtx.Lock()
	log.Tracef("Updating last block height of peer %v from %v to %v",
		p.addr, p.lastBlock, newHeight)
	p.lastBlock = int32(newHeight)
	p.statsMtx.Unlock()
}

// UpdateLastAnnouncedBlock updates meta-data about the last block sha this
// peer is known to have announced. It is safe for concurrent access.
func (p *Peer) UpdateLastAnnouncedBlock(blkSha *wire.ShaHash) {
	log.Tracef("Updating last blk for peer %v, %v", p.addr, blkSha)

	p.statsMtx.Lock()
	p.lastAnnouncedBlock = blkSha
	p.statsMtx.Unlock()
}

// AddKnownInventory adds the passed inventory to the cache of known inventory
// for the peer.  It is safe for concurrent access.
func (p *Peer) AddKnownInventory(invVect *wire.InvVect) {
	p.knownInventory.Add(invVect)
}

// StatsSnapshot returns a snapshot of the current peer flags and statistics.
func (p *Peer) StatsSnapshot() *StatsSnap {
	p.statsMtx.RLock()
	defer p.statsMtx.RUnlock()

	p.flagsMtx.Lock()
	id := p.id
	addr := p.addr
	userAgent := p.userAgent
	services := p.services
	protocolVersion := p.protocolVersion
	p.flagsMtx.Unlock()

	// Get a copy of all relevant flags and stats.
	return &StatsSnap{
		ID:             id,
		Addr:           addr,
		UserAgent:      userAgent,
		Services:       services,
		LastSend:       p.lastSend,
		LastRecv:       p.lastRecv,
		BytesSent:      p.bytesSent,
		BytesRecv:      p.bytesReceived,
		ConnTime:       p.timeConnected,
		TimeOffset:     p.timeOffset,
		Version:        protocolVersion,
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
func (p *Peer) Addr() string {
	// The address doesn't change after initialization, therefore it is not
	// protected by a mutex.
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
	p.flagsMtx.Lock()
	defer p.flagsMtx.Unlock()

	return p.versionKnown
}

// VerAckReceived returns whether or not a verack message was received by the
// peer.  It is safe for concurrent accecss.
func (p *Peer) VerAckReceived() bool {
	p.flagsMtx.Lock()
	defer p.flagsMtx.Unlock()

	return p.verAckReceived
}

// ProtocolVersion returns the peer protocol version in a manner that is safe
// for concurrent access.
func (p *Peer) ProtocolVersion() uint32 {
	p.flagsMtx.Lock()
	defer p.flagsMtx.Unlock()

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
	var blockNum int32
	if p.cfg.NewestBlock != nil {
		var err error
		_, blockNum, err = p.cfg.NewestBlock()
		if err != nil {
			return err
		}
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

	ourNA := p.na
	if p.cfg.BestLocalAddress != nil {
		ourNA = p.cfg.BestLocalAddress(p.na)
	}

	// Generate a unique nonce for this peer so self connections can be
	// detected.  This is accomplished by adding it to a size-limited map of
	// recently seen nonces.
	nonce, err := wire.RandomUint64()
	if err != nil {
		fmt.Println(err)
		return err
	}
	sentNonces.Add(nonce)

	// Version message.
	msg := wire.NewMsgVersion(ourNA, theirNa, nonce, int32(blockNum))
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
	msg.ProtocolVersion = int32(p.ProtocolVersion())

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
	if !allowSelfConns && sentNonces.Exists(msg.Nonce) {
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
		log.Errorf("Only one version message per peer is allowed %s.",
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
	p.lastBlock = msg.LastBlock
	p.startingHeight = msg.LastBlock
	// Set the peer's time offset.
	p.timeOffset = msg.Timestamp.Unix() - time.Now().Unix()
	p.statsMtx.Unlock()

	// Negotiate the protocol version.
	p.flagsMtx.Lock()
	p.protocolVersion = minUint32(p.protocolVersion, uint32(msg.ProtocolVersion))
	p.versionKnown = true
	log.Debugf("Negotiated protocol version %d for peer %s",
		p.protocolVersion, p)
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
			log.Errorf("Can't get remote address: %v", err)
			p.Disconnect()
			return
		}
		p.na = na

		// Send version.
		err = p.pushVersionMsg()
		if err != nil {
			log.Errorf("Can't send version message to %s: %v",
				p, err)
			p.Disconnect()
			return
		}
	}

	// Send verack.
	p.QueueMessage(wire.NewMsgVerAck(), nil)
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
	if p.ProtocolVersion() > wire.BIP0031Version &&
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
		log.Errorf("Can't send message to %s: %v", p, err)
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

// shouldHandleReadError returns whether or not the passed error, which is
// expected to have come from reading from the remote peer in the inHandler,
// should be logged and responded to with a reject message.
func (p *Peer) shouldHandleReadError(err error) bool {
	// No logging or reject message when the peer is being forcibly
	// disconnected.
	if atomic.LoadInt32(&p.disconnect) != 0 {
		return false
	}

	// No logging or reject message when the remote peer has been
	// disconnected.
	if err == io.EOF {
		return false
	}
	if opErr, ok := err.(*net.OpError); ok && !opErr.Temporary() {
		return false
	}

	return true
}

// inHandler handles all incoming messages for the peer.  It must be run as a
// goroutine.
func (p *Peer) inHandler() {
	// Peers must complete the initial version negotiation within a shorter
	// timeframe than a general idle timeout.  The timer is then reset below
	// to idleTimeout for all future messages.
	idleTimer := time.AfterFunc(negotiateTimeout, func() {
		if p.VersionKnown() {
			log.Warnf("Peer %s no answer for %d minutes, "+
				"disconnecting", p, negotiateTimeout)
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
				idleTimer.Reset(idleTimeout)
				continue
			}

			// Only log the error and send reject message if the
			// local peer is not forcibly disconnecting and the
			// remote peer has not disconnected.
			if p.shouldHandleReadError(err) {
				errMsg := fmt.Sprintf("Can't read message "+
					"from %s: %v", p, err)
				log.Errorf(errMsg)

				// Push a reject message for the malformed
				// message and wait for the message to be sent
				// before disconnecting.
				//
				// NOTE: Ideally this would include the command
				// in the header if at least that much of the
				// message was valid, but that is not currently
				// exposed by wire, so just used malformed for
				// the command.
				p.PushRejectMsg("malformed",
					wire.RejectMalformed, errMsg, nil, true)
			}
			break out
		}
		p.statsMtx.Lock()
		p.lastRecv = time.Now()
		p.statsMtx.Unlock()

		// Ensure version message comes first.
		if vmsg, ok := rmsg.(*wire.MsgVersion); !ok && !p.VersionKnown() {
			errStr := "A version message must precede all others"
			log.Errorf(errStr)

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
			if p.cfg.Listeners != nil && p.cfg.Listeners.VersionListener != nil {
				p.cfg.Listeners.VersionListener(p, msg)
			}

		case *wire.MsgVerAck:
			p.flagsMtx.Lock()
			versionSent := p.versionSent
			p.flagsMtx.Unlock()

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
			p.flagsMtx.Lock()
			p.verAckReceived = true
			p.flagsMtx.Unlock()
			if p.cfg.Listeners != nil && p.cfg.Listeners.VerAckListener != nil {
				p.cfg.Listeners.VerAckListener(p, msg)
			}

		case *wire.MsgGetAddr:
			if p.cfg.Listeners != nil && p.cfg.Listeners.GetAddrListener != nil {
				p.cfg.Listeners.GetAddrListener(p, msg)
			}

		case *wire.MsgAddr:
			if p.cfg.Listeners != nil && p.cfg.Listeners.AddrListener != nil {
				p.cfg.Listeners.AddrListener(p, msg)
			}

		case *wire.MsgPing:
			p.handlePingMsg(msg)
			if p.cfg.Listeners != nil && p.cfg.Listeners.PingListener != nil {
				p.cfg.Listeners.PingListener(p, msg)
			}

		case *wire.MsgPong:
			p.handlePongMsg(msg)
			if p.cfg.Listeners != nil && p.cfg.Listeners.PongListener != nil {
				p.cfg.Listeners.PongListener(p, msg)
			}

		case *wire.MsgAlert:
			// Note: The reference client currently bans peers that send alerts
			// not signed with its key.  We could verify against their key, but
			// since the reference client is currently unwilling to support
			// other implementions' alert messages, we will not relay theirs.
			if p.cfg.Listeners != nil && p.cfg.Listeners.AlertListener != nil {
				p.cfg.Listeners.AlertListener(p, msg)
			}

		case *wire.MsgMemPool:
			if p.cfg.Listeners != nil && p.cfg.Listeners.MemPoolListener != nil {
				p.cfg.Listeners.MemPoolListener(p, msg)
			}

		case *wire.MsgTx:
			if p.cfg.Listeners != nil && p.cfg.Listeners.TxListener != nil {
				p.cfg.Listeners.TxListener(p, msg)
			}

		case *wire.MsgBlock:
			if p.blockStallCancel != nil {
				close(p.blockStallCancel)
			}
			if p.cfg.Listeners != nil && p.cfg.Listeners.BlockListener != nil {
				p.cfg.Listeners.BlockListener(p, msg, buf)
			}

		case *wire.MsgInv:
			if p.cfg.Listeners != nil && p.cfg.Listeners.InvListener != nil {
				p.cfg.Listeners.InvListener(p, msg)
			}

		case *wire.MsgHeaders:
			if p.cfg.Listeners != nil && p.cfg.Listeners.HeadersListener != nil {
				p.cfg.Listeners.HeadersListener(p, msg)
			}

		case *wire.MsgNotFound:
			if p.cfg.Listeners != nil && p.cfg.Listeners.NotFoundListener != nil {
				p.cfg.Listeners.NotFoundListener(p, msg)
			}

		case *wire.MsgGetData:
			if p.cfg.Listeners != nil && p.cfg.Listeners.GetDataListener != nil {
				p.cfg.Listeners.GetDataListener(p, msg)
			}

		case *wire.MsgGetBlocks:
			if p.cfg.Listeners != nil && p.cfg.Listeners.GetBlocksListener != nil {
				p.cfg.Listeners.GetBlocksListener(p, msg)
			}

		case *wire.MsgGetHeaders:
			if p.cfg.Listeners != nil && p.cfg.Listeners.GetHeadersListener != nil {
				p.cfg.Listeners.GetHeadersListener(p, msg)
			}

		case *wire.MsgFilterAdd:
			if p.cfg.Listeners != nil && p.cfg.Listeners.FilterAddListener != nil {
				p.cfg.Listeners.FilterAddListener(p, msg)
			}

		case *wire.MsgFilterClear:
			if p.cfg.Listeners != nil && p.cfg.Listeners.FilterClearListener != nil {
				p.cfg.Listeners.FilterClearListener(p, msg)
			}

		case *wire.MsgFilterLoad:
			if p.cfg.Listeners != nil && p.cfg.Listeners.FilterLoadListener != nil {
				p.cfg.Listeners.FilterLoadListener(p, msg)
			}

		case *wire.MsgReject:
			if p.cfg.Listeners != nil && p.cfg.Listeners.RejectListener != nil {
				p.cfg.Listeners.RejectListener(p, msg)
			}

		default:
			log.Debugf("Received unhandled message of type %v:",
				rmsg.Command())
		}

		// ok we got a message, reset the timer.
		// timer just calls p.Disconnect() after logging.
		idleTimer.Reset(idleTimeout)
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
	trickleTicker := time.NewTicker(trickleTimeout)
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
			p.sendQueue <- msg
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
			p.sendQueue <- val.(outMsg)

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
	close(p.queueQuit)
	log.Tracef("Peer queue handler done for %s", p)
}

// invContainsBlock returns true if the passed InvList contains an Inv of type
// InvTypeBlock. Otherwise, it returns false.
func invContainsBlock(invList []*wire.InvVect) bool {
	for _, inv := range invList {
		if inv.Type == wire.InvTypeBlock {
			return true
		}
	}
	return false
}

// outHandler handles all outgoing messages for the peer.  It must be run as a
// goroutine.  It uses a buffered channel to serialize output messages while
// allowing the sender to continue running asynchronously.
func (p *Peer) outHandler() {
	pingTimer := time.AfterFunc(pingTimeout, func() {
		nonce, err := wire.RandomUint64()
		if err != nil {
			log.Errorf("Not sending ping on timeout to %s: %v",
				p, err)
			return
		}
		p.QueueMessage(wire.NewMsgPing(nonce), nil)
	})
	var blockStallActive bool
	var stallTimeout time.Duration
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
			reset := true
			switch m := msg.msg.(type) {
			case *wire.MsgVersion:
				// should get a verack
				p.flagsMtx.Lock()
				p.versionSent = true
				p.flagsMtx.Unlock()
			case *wire.MsgGetAddr:
				// should get addresses
			case *wire.MsgPing:
				// expects pong
				// Also set up statistics.
				p.statsMtx.Lock()
				if p.ProtocolVersion() > wire.BIP0031Version {
					p.lastPingNonce = m.Nonce
					p.lastPingTime = time.Now()
				}
				p.statsMtx.Unlock()
			case *wire.MsgMemPool:
				// Should return an inv.
			case *wire.MsgGetData:
				// Should get us block, tx, or not found.

				// If the blockStallTimer has not already been
				// started, then initialize the timer to fire
				// off a read in BlockStallTimeout seconds.
				// Additionally, create a cancellation channel
				// so the inHandler can signal us if a MsgBlock
				// comes in time.
				gdmsg := msg.msg.(*wire.MsgGetData)
				if blockStallActive && p.blockStallTimer == nil &&
					invContainsBlock(gdmsg.InvList) {
					log.Debugf("Starting block stall timer for: %v", p)
					p.blockStallTimer = time.After(stallTimeout)
					p.blockStallCancel = make(chan struct{})
				}
			case *wire.MsgGetHeaders:
				// Should get us headers back.
			default:
				// Not one of the above, no sure reply.
				// We want to ping if nothing else
				// interesting happens.
				reset = false
			}
			if reset {
				pingTimer.Reset(pingTimeout)
			}
			p.writeMessage(msg.msg)
			p.statsMtx.Lock()
			p.lastSend = time.Now()
			p.statsMtx.Unlock()
			if msg.doneChan != nil {
				msg.doneChan <- struct{}{}
			}
			p.sendDoneQueue <- struct{}{}

		case timeout := <-p.blockStallActivate:
			log.Debugf("Activating block stall timer (%v "+
				"seconds) for: %v", timeout, p)
			blockStallActive = true
			stallTimeout = timeout
		case <-p.blockStallCancel:
			// The inHandler received a MsgBlock before
			// BlockStallTimeout seconds had elapsed. So we set the
			// blockStallTimer and blockStallCancel to nil so the
			//select loop won't block on those cases in the future.
			log.Debugf("Stopping block stall timer for: %v", p)
			p.blockStallTimer = nil
			p.blockStallCancel = nil
			blockStallActive = false
		case <-p.blockStallTimer:
			// The inHandler didn't receive a MsgBlock before
			// BlockStallTimeout seconds had elapsed. So we
			// disconnect the peer for stalling block download.
			log.Warnf("Peer %s is stalling initial "+
				"block download, no block response for %v "+
				"seconds disconnecting", p, BlockStallTimeout)
			p.Disconnect()
		case <-p.quit:
			break out
		}
	}

	pingTimer.Stop()

	<-p.queueQuit

	// Drain any wait channels before we go away so we don't leave something
	// waiting for us. We have waited on queueQuit and thus we can be sure
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

// Connect uses the given conn to connect to the peer.
func (p *Peer) Connect(conn net.Conn) error {
	p.conn = conn
	p.timeConnected = time.Now()

	// Connection was successful so log it and start peer.
	log.Debugf("Connected to %s", p.conn.RemoteAddr())
	atomic.AddInt32(&p.connected, 1)
	return p.Start()
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
			log.Errorf("Can't send outbound version message %v", err)
			p.Disconnect()
			return err
		}
	}

	// Start processing input and output.
	go p.inHandler()
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

// newPeerBase returns a new base bitcoin peer based on the inbound flag.  This
// is used by the NewInboundPeer and NewOutboundPeer functions to perform base
// setup needed by both types of peers.
func newPeerBase(cfg *Config, inbound bool) *Peer {
	// If provided, use the configured version, else default to the max
	// supported version.
	var protocolVersion uint32
	if cfg.ProtocolVersion != 0 {
		protocolVersion = cfg.ProtocolVersion
	} else {
		protocolVersion = MaxProtocolVersion
	}

	p := Peer{
		btcnet:             cfg.Net,
		inbound:            inbound,
		knownInventory:     NewMruInventoryMap(maxKnownInventory),
		outputQueue:        make(chan outMsg, outputBufferSize),
		sendQueue:          make(chan outMsg, 1),   // nonblocking sync
		sendDoneQueue:      make(chan struct{}, 1), // nonblocking sync
		outputInvChan:      make(chan *wire.InvVect, outputBufferSize),
		blockStallActivate: make(chan time.Duration),
		queueQuit:          make(chan struct{}),
		quit:               make(chan struct{}),
		stats:              stats{},
		cfg:                cfg,
		services:           cfg.Services,
		protocolVersion:    protocolVersion,
	}
	return &p
}

// NewInboundPeer returns a new inbound bitcoin peer. Use Start to begin
// processing incoming and outgoing messages.
func NewInboundPeer(cfg *Config, conn net.Conn) *Peer {
	p := newPeerBase(cfg, true)
	p.conn = conn
	p.addr = conn.RemoteAddr().String()
	p.timeConnected = time.Now()
	atomic.AddInt32(&p.connected, 1)
	return p
}

// NewOutboundPeer returns a new outbound bitcoin peer.
func NewOutboundPeer(cfg *Config, na *wire.NetAddress) *Peer {
	p := newPeerBase(cfg, false)
	p.na = na
	p.addr = fmt.Sprintf("%v:%v", na.IP, na.Port)
	return p
}

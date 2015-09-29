// Copyright (c) 2013-2014 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	mrand "math/rand"
	"net"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/btcsuite/btcd/addrmgr"
	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/database"
	"github.com/btcsuite/btcd/peer"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil"
	"github.com/btcsuite/btcutil/bloom"
)

const (
	// These constants are used by the DNS seed code to pick a random last
	// seen time.
	secondsIn3Days int32 = 24 * 60 * 60 * 3
	secondsIn4Days int32 = 24 * 60 * 60 * 4
)

const (
	// defaultServices describes the default services that are supported by
	// the server.
	defaultServices = wire.SFNodeNetwork | wire.SFNodeBloom

	// defaultMaxOutbound is the default number of max outbound peers.
	defaultMaxOutbound = 8

	// connectionRetryInterval is the base amount of time to wait in between
	// retries when connecting to persistent peers.  It is adjusted by the
	// number of retries such that there is a retry backoff.
	connectionRetryInterval = time.Second * 10

	// maxConnectionRetryInterval is the max amount of time retrying of a
	// persistent peer is allowed to grow to.  This is necessary since the
	// retry logic uses a backoff mechanism which increases the interval
	// base done the number of retries that have been done.
	maxConnectionRetryInterval = time.Minute * 5
)

var (
	// userAgentName is the user agent name and is used to help identify
	// ourselves to other bitcoin peers.
	userAgentName = "btcd"

	// userAgentVersion is the user agent version and is used to help
	// identify ourselves to other bitcoin peers.
	userAgentVersion = fmt.Sprintf("%d.%d.%d", appMajor, appMinor, appPatch)
)

// broadcastMsg provides the ability to house a bitcoin message to be broadcast
// to all connected peers except specified excluded peers.
type broadcastMsg struct {
	message      wire.Message
	excludePeers []*peer.Peer
}

// broadcastInventoryAdd is a type used to declare that the InvVect it contains
// needs to be added to the rebroadcast map
type broadcastInventoryAdd relayMsg

// broadcastInventoryDel is a type used to declare that the InvVect it contains
// needs to be removed from the rebroadcast map
type broadcastInventoryDel *wire.InvVect

// relayMsg packages an inventory vector along with the newly discovered
// inventory so the relay has access to that information.
type relayMsg struct {
	invVect *wire.InvVect
	data    interface{}
}

// updatePeerHeightsMsg is a message sent from the blockmanager to the server
// after a new block has been accepted. The purpose of the message is to update
// the heights of peers that were known to announce the block before we
// connected it to the main chain or recognized it as an orphan. With these
// updates, peer heights will be kept up to date, allowing for fresh data when
// selecting sync peer candidacy.
type updatePeerHeightsMsg struct {
	newSha     *wire.ShaHash
	newHeight  int32
	originPeer *peer.Peer
}

// server provides a bitcoin server for handling communications to and from
// bitcoin peers.
type server struct {
	nonce                uint64
	listeners            []net.Listener
	chainParams          *chaincfg.Params
	started              int32      // atomic
	shutdown             int32      // atomic
	shutdownSched        int32      // atomic
	bytesMutex           sync.Mutex // For the following two fields.
	bytesReceived        uint64     // Total bytes received from all peers since start.
	bytesSent            uint64     // Total bytes sent by all peers since start.
	addrManager          *addrmgr.AddrManager
	rpcServer            *rpcServer
	blockManager         *blockManager
	addrIndexer          *addrIndexer
	txMemPool            *txMemPool
	cpuMiner             *CPUMiner
	modifyRebroadcastInv chan interface{}
	newPeers             chan *peer.Peer
	donePeers            chan *peer.Peer
	banPeers             chan *peer.Peer
	retryPeers           chan *peer.Peer
	wakeup               chan struct{}
	query                chan interface{}
	relayInv             chan relayMsg
	broadcast            chan broadcastMsg
	peerHeightsUpdate    chan updatePeerHeightsMsg
	wg                   sync.WaitGroup
	quit                 chan struct{}
	nat                  NAT
	db                   database.Db
	timeSource           blockchain.MedianTimeSource
	services             wire.ServiceFlag
}

type peerState struct {
	peers            map[*peer.Peer]struct{}
	outboundPeers    map[*peer.Peer]struct{}
	persistentPeers  map[*peer.Peer]struct{}
	banned           map[string]time.Time
	outboundGroups   map[string]int
	maxOutboundPeers int
}

// randomUint16Number returns a random uint16 in a specified input range.  Note
// that the range is in zeroth ordering; if you pass it 1800, you will get
// values from 0 to 1800.
func randomUint16Number(max uint16) uint16 {
	// In order to avoid modulo bias and ensure every possible outcome in
	// [0, max) has equal probability, the random number must be sampled
	// from a random source that has a range limited to a multiple of the
	// modulus.
	var randomNumber uint16
	var limitRange = (math.MaxUint16 / max) * max
	for {
		binary.Read(rand.Reader, binary.LittleEndian, &randomNumber)
		if randomNumber < limitRange {
			return (randomNumber % max)
		}
	}
}

// AddRebroadcastInventory adds 'iv' to the list of inventories to be
// rebroadcasted at random intervals until they show up in a block.
func (s *server) AddRebroadcastInventory(iv *wire.InvVect, data interface{}) {
	// Ignore if shutting down.
	if atomic.LoadInt32(&s.shutdown) != 0 {
		return
	}

	s.modifyRebroadcastInv <- broadcastInventoryAdd{invVect: iv, data: data}
}

// RemoveRebroadcastInventory removes 'iv' from the list of items to be
// rebroadcasted if present.
func (s *server) RemoveRebroadcastInventory(iv *wire.InvVect) {
	// Ignore if shutting down.
	if atomic.LoadInt32(&s.shutdown) != 0 {
		return
	}

	s.modifyRebroadcastInv <- broadcastInventoryDel(iv)
}

// pushTxMsg sends a tx message for the provided transaction hash to the
// connected peer.  An error is returned if the transaction hash is not known.
func (s *server) pushTxMsg(p *peer.Peer, sha *wire.ShaHash, doneChan, waitChan chan struct{}) error {
	// Attempt to fetch the requested transaction from the pool.  A
	// call could be made to check for existence first, but simply trying
	// to fetch a missing transaction results in the same behavior.
	tx, err := s.txMemPool.FetchTransaction(sha)
	if err != nil {
		peerLog.Tracef("Unable to fetch tx %v from transaction "+
			"pool: %v", sha, err)

		if doneChan != nil {
			doneChan <- struct{}{}
		}
		return err
	}

	// Once we have fetched data wait for any previous operation to finish.
	if waitChan != nil {
		<-waitChan
	}

	p.QueueMessage(tx.MsgTx(), doneChan)

	return nil
}

// pushBlockMsg sends a block message for the provided block hash to the
// connected peer.  An error is returned if the block hash is not known.
func (s *server) pushBlockMsg(p *peer.Peer, sha *wire.ShaHash, doneChan, waitChan chan struct{}) error {
	blk, err := s.db.FetchBlockBySha(sha)
	if err != nil {
		peerLog.Tracef("Unable to fetch requested block sha %v: %v",
			sha, err)

		if doneChan != nil {
			doneChan <- struct{}{}
		}
		return err
	}

	// Once we have fetched data wait for any previous operation to finish.
	if waitChan != nil {
		<-waitChan
	}

	// We only send the channel for this message if we aren't sending
	// an inv straight after.
	var dc chan struct{}
	pInfo, err := s.blockManager.peerInfo(p)
	if err != nil {
		bmgrLog.Errorf("%v", err)
		if doneChan != nil {
			doneChan <- struct{}{}
		}
		return nil
	}
	continueHash := pInfo.continueHash
	sendInv := continueHash != nil && continueHash.IsEqual(sha)
	if !sendInv {
		dc = doneChan
	}
	p.QueueMessage(blk.MsgBlock(), dc)

	// When the peer requests the final block that was advertised in
	// response to a getblocks message which requested more blocks than
	// would fit into a single message, send it a new inventory message
	// to trigger it to issue another getblocks message for the next
	// batch of inventory.
	if sendInv {
		hash, _, err := s.db.NewestSha()
		if err == nil {
			invMsg := wire.NewMsgInvSizeHint(1)
			iv := wire.NewInvVect(wire.InvTypeBlock, hash)
			invMsg.AddInvVect(iv)
			p.QueueMessage(invMsg, doneChan)
			pInfo.continueHash = nil
		} else if doneChan != nil {
			doneChan <- struct{}{}
		}
	}
	return nil
}

// pushMerkleBlockMsg sends a merkleblock message for the provided block hash to
// the connected peer.  Since a merkle block requires the peer to have a filter
// loaded, this call will simply be ignored if there is no filter loaded.  An
// error is returned if the block hash is not known.
func (s *server) pushMerkleBlockMsg(p *peer.Peer, sha *wire.ShaHash, doneChan, waitChan chan struct{}) error {
	pInfo, err := s.blockManager.peerInfo(p)
	if err != nil {
		bmgrLog.Errorf("%v", err)
		if doneChan != nil {
			doneChan <- struct{}{}
		}
		return nil
	}
	// Do not send a response if the peer doesn't have a filter loaded.
	if !pInfo.filter.IsLoaded() {
		if doneChan != nil {
			doneChan <- struct{}{}
		}
		return nil
	}

	blk, err := s.db.FetchBlockBySha(sha)
	if err != nil {
		peerLog.Tracef("Unable to fetch requested block sha %v: %v",
			sha, err)

		if doneChan != nil {
			doneChan <- struct{}{}
		}
		return err
	}

	// Generate a merkle block by filtering the requested block according
	// to the filter for the peer.
	merkle, matchedTxIndices := bloom.NewMerkleBlock(blk, pInfo.filter)

	// Once we have fetched data wait for any previous operation to finish.
	if waitChan != nil {
		<-waitChan
	}

	// Send the merkleblock.  Only send the done channel with this message
	// if no transactions will be sent afterwards.
	var dc chan struct{}
	if len(matchedTxIndices) == 0 {
		dc = doneChan
	}
	p.QueueMessage(merkle, dc)

	// Finally, send any matched transactions.
	blkTransactions := blk.MsgBlock().Transactions
	for i, txIndex := range matchedTxIndices {
		// Only send the done channel on the final transaction.
		var dc chan struct{}
		if i == len(matchedTxIndices)-1 {
			dc = doneChan
		}
		if txIndex < uint32(len(blkTransactions)) {
			p.QueueMessage(blkTransactions[txIndex], dc)
		}
	}

	return nil
}

// handleVersionMsg is invoked when a peer receives a version bitcoin message
// and is used to negotiate the protocol version details as well as kick start
// the communications.
func (s *server) handleVersionMsg(p *peer.Peer, msg *wire.MsgVersion) {
	// Add the remote peer time as a sample for creating an offset against
	// the local clock to keep the network time in sync.
	s.timeSource.AddTimeSample(p.Addr(), msg.Timestamp)

	// Signal the block manager this peer is a new sync candidate.
	s.blockManager.NewPeer(p)
	pInfo, err := s.blockManager.peerInfo(p)
	if err != nil {
		bmgrLog.Errorf("%v", err)
		return
	}

	// Choose whether or not to relay transactions before a filter command
	// is received.
	pInfo.relayMtx.Lock()
	pInfo.disableRelayTx = msg.DisableRelayTx
	pInfo.relayMtx.Unlock()

	// Update the address manager and request known addresses from the
	// remote peer for outbound connections.  This is skipped when running
	// on the simulation test network since it is only intended to connect
	// to specified peers and actively avoids advertising and connecting to
	// discovered peers.
	if !cfg.SimNet {
		// Outbound connections.
		if !p.Inbound() {
			// TODO(davec): Only do this if not doing the initial block
			// download and the local address is routable.
			if !cfg.DisableListen /* && isCurrent? */ {
				// Get address that best matches.
				lna := s.addrManager.GetBestLocalAddress(p.NA())
				if addrmgr.IsRoutable(lna) {
					// Filter addresses the peer already knows about.
					if !pInfo.addressKnown(addrmgr.NetAddressKey(lna)) {
						addresses := []*wire.NetAddress{lna}
						p.PushAddrMsg(addresses)
						pInfo.addKnownAddress(addrmgr.NetAddressKey(lna))
					}
				}
			}

			// Request known addresses if the server address manager needs
			// more and the peer has a protocol version new enough to
			// include a timestamp with addresses.
			hasTimestamp := p.ProtocolVersion() >=
				wire.NetAddressTimeVersion
			if s.addrManager.NeedMoreAddresses() && hasTimestamp {
				p.QueueMessage(wire.NewMsgGetAddr(), nil)
			}

			// Mark the address as a known good address.
			s.addrManager.Good(p.NA())
		} else {
			// A peer might not be advertising the same address that it
			// actually connected from.  One example of why this can happen
			// is with NAT.  Only add the address to the address manager if
			// the addresses agree.
			if addrmgr.NetAddressKey(&msg.AddrMe) == addrmgr.NetAddressKey(p.NA()) {
				s.addrManager.AddAddress(p.NA(), p.NA())
				s.addrManager.Good(p.NA())
			}
		}
	}
}

// handleMemPoolMsg is invoked when a peer receives a mempool bitcoin message.
// It creates and sends an inventory message with the contents of the memory
// pool up to the maximum inventory allowed per message.  When the peer has a
// bloom filter loaded, the contents are filtered accordingly.
func (s *server) handleMemPoolMsg(p *peer.Peer, msg *wire.MsgMemPool) {
	// Generate inventory message with the available transactions in the
	// transaction memory pool.  Limit it to the max allowed inventory
	// per message.  The the NewMsgInvSizeHint function automatically limits
	// the passed hint to the maximum allowed, so it's safe to pass it
	// without double checking it here.
	txDescs := s.txMemPool.TxDescs()
	invMsg := wire.NewMsgInvSizeHint(uint(len(txDescs)))

	for i, txDesc := range txDescs {
		// Another thread might have removed the transaction from the
		// pool since the initial query.
		hash := txDesc.Tx.Sha()
		if !s.txMemPool.IsTransactionInPool(hash) {
			continue
		}

		pInfo, err := s.blockManager.peerInfo(p)
		if err != nil {
			bmgrLog.Errorf("%v", err)
			return
		}
		// Either add all transactions when there is no bloom filter,
		// or only the transactions that match the filter when there is
		// one.
		if !pInfo.filter.IsLoaded() || pInfo.filter.MatchTxAndUpdate(txDesc.Tx) {
			iv := wire.NewInvVect(wire.InvTypeTx, hash)
			invMsg.AddInvVect(iv)
			if i+1 >= wire.MaxInvPerMsg {
				break
			}
		}
	}

	// Send the inventory message if there is anything to send.
	if len(invMsg.InvList) > 0 {
		p.QueueMessage(invMsg, nil)
	}
}

// handleTxMsg is invoked when a peer receives a tx bitcoin message.  It blocks
// until the bitcoin transaction has been fully processed.  Unlock the block
// handler this does not serialize all transactions through a single thread
// transactions don't rely on the previous one in a linear fashion like blocks.
func (s *server) handleTxMsg(p *peer.Peer, msg *wire.MsgTx) {
	// Add the transaction to the known inventory for the peer.
	// Convert the raw MsgTx to a btcutil.Tx which provides some convenience
	// methods and things such as hash caching.
	tx := btcutil.NewTx(msg)
	iv := wire.NewInvVect(wire.InvTypeTx, tx.Sha())
	p.AddKnownInventory(iv)

	// Queue the transaction up to be handled by the block manager and
	// intentionally block further receives until the transaction is fully
	// processed and known good or bad.  This helps prevent a malicious peer
	// from queueing up a bunch of bad transactions before disconnecting (or
	// being disconnected) and wasting memory.
	s.blockManager.QueueTx(tx, p)
	pInfo, err := s.blockManager.peerInfo(p)
	if err != nil {
		bmgrLog.Errorf("%v", err)
		return
	}
	<-pInfo.txProcessed
}

// handleBlockMsg is invoked when a peer receives a block bitcoin message.  It
// blocks until the bitcoin block has been fully processed.
func (s *server) handleBlockMsg(p *peer.Peer, msg *wire.MsgBlock, buf []byte) {
	// Convert the raw MsgBlock to a btcutil.Block which provides some
	// convenience methods and things such as hash caching.
	block := btcutil.NewBlockFromBlockAndBytes(msg, buf)

	// Add the block to the known inventory for the peer.
	iv := wire.NewInvVect(wire.InvTypeBlock, block.Sha())
	p.AddKnownInventory(iv)

	// Queue the block up to be handled by the block
	// manager and intentionally block further receives
	// until the bitcoin block is fully processed and known
	// good or bad.  This helps prevent a malicious peer
	// from queueing up a bunch of bad blocks before
	// disconnecting (or being disconnected) and wasting
	// memory.  Additionally, this behavior is depended on
	// by at least the block acceptance test tool as the
	// reference implementation processes blocks in the same
	// thread and therefore blocks further messages until
	// the bitcoin block has been fully processed.
	s.blockManager.QueueBlock(block, p)
	pInfo, err := s.blockManager.peerInfo(p)
	if err != nil {
		bmgrLog.Errorf("%v", err)
		return
	}
	<-pInfo.blockProcessed
}

// handleInvMsg is invoked when a peer receives an inv bitcoin message and is
// used to examine the inventory being advertised by the remote peer and react
// accordingly.  We pass the message down to blockmanager which will call
// QueueMessage with any appropriate responses.
func (s *server) handleInvMsg(p *peer.Peer, msg *wire.MsgInv) {
	s.blockManager.QueueInv(msg, p)
}

// handleHeadersMsg is invoked when a peer receives a headers bitcoin
// message.  The message is passed down to the block manager.
func (s *server) handleHeadersMsg(p *peer.Peer, msg *wire.MsgHeaders) {
	s.blockManager.QueueHeaders(msg, p)
}

// handleGetData is invoked when a peer receives a getdata bitcoin message and
// is used to deliver block and transaction information.
func (s *server) handleGetDataMsg(p *peer.Peer, msg *wire.MsgGetData) {
	numAdded := 0
	notFound := wire.NewMsgNotFound()

	// We wait on this wait channel periodically to prevent queueing
	// far more data than we can send in a reasonable time, wasting memory.
	// The waiting occurs after the database fetch for the next one to
	// provide a little pipelining.
	var waitChan chan struct{}
	doneChan := make(chan struct{}, 1)

	for i, iv := range msg.InvList {
		var c chan struct{}
		// If this will be the last message we send.
		if i == len(msg.InvList)-1 && len(notFound.InvList) == 0 {
			c = doneChan
		} else if (i+1)%3 == 0 {
			// Buffered so as to not make the send goroutine block.
			c = make(chan struct{}, 1)
		}
		var err error
		switch iv.Type {
		case wire.InvTypeTx:
			err = s.pushTxMsg(p, &iv.Hash, c, waitChan)
		case wire.InvTypeBlock:
			err = s.pushBlockMsg(p, &iv.Hash, c, waitChan)
		case wire.InvTypeFilteredBlock:
			err = s.pushMerkleBlockMsg(p, &iv.Hash, c, waitChan)
		default:
			peerLog.Warnf("Unknown type in inventory request %d",
				iv.Type)
			continue
		}
		if err != nil {
			notFound.AddInvVect(iv)

			// When there is a failure fetching the final entry
			// and the done channel was sent in due to there
			// being no outstanding not found inventory, consume
			// it here because there is now not found inventory
			// that will use the channel momentarily.
			if i == len(msg.InvList)-1 && c != nil {
				<-c
			}
		}
		numAdded++
		waitChan = c
	}
	if len(notFound.InvList) != 0 {
		p.QueueMessage(notFound, doneChan)
	}

	// Wait for messages to be sent. We can send quite a lot of data at this
	// point and this will keep the peer busy for a decent amount of time.
	// We don't process anything else by them in this time so that we
	// have an idea of when we should hear back from them - else the idle
	// timeout could fire when we were only half done sending the blocks.
	if numAdded > 0 {
		<-doneChan
	}
}

// handleGetBlocksMsg is invoked when a peer receives a getblocks bitcoin
// message.
func (s *server) handleGetBlocksMsg(p *peer.Peer, msg *wire.MsgGetBlocks) {
	// Return all block hashes to the latest one (up to max per message) if
	// no stop hash was specified.
	// Attempt to find the ending index of the stop hash if specified.
	endIdx := database.AllShas
	if !msg.HashStop.IsEqual(&zeroHash) {
		height, err := s.db.FetchBlockHeightBySha(&msg.HashStop)
		if err == nil {
			endIdx = height + 1
		}
	}

	// Find the most recent known block based on the block locator.
	// Use the block after the genesis block if no other blocks in the
	// provided locator are known.  This does mean the client will start
	// over with the genesis block if unknown block locators are provided.
	// This mirrors the behavior in the reference implementation.
	startIdx := int32(1)
	for _, hash := range msg.BlockLocatorHashes {
		height, err := s.db.FetchBlockHeightBySha(hash)
		if err == nil {
			// Start with the next hash since we know this one.
			startIdx = height + 1
			break
		}
	}

	// Don't attempt to fetch more than we can put into a single message.
	autoContinue := false
	if endIdx-startIdx > wire.MaxBlocksPerMsg {
		endIdx = startIdx + wire.MaxBlocksPerMsg
		autoContinue = true
	}

	// Generate inventory message.
	//
	// The FetchBlockBySha call is limited to a maximum number of hashes
	// per invocation.  Since the maximum number of inventory per message
	// might be larger, call it multiple times with the appropriate indices
	// as needed.
	invMsg := wire.NewMsgInv()
	for start := startIdx; start < endIdx; {
		// Fetch the inventory from the block database.
		hashList, err := s.db.FetchHeightRange(start, endIdx)
		if err != nil {
			peerLog.Warnf("Block lookup failed: %v", err)
			return
		}

		// The database did not return any further hashes.  Break out of
		// the loop now.
		if len(hashList) == 0 {
			break
		}

		// Add block inventory to the message.
		for _, hash := range hashList {
			hashCopy := hash
			iv := wire.NewInvVect(wire.InvTypeBlock, &hashCopy)
			invMsg.AddInvVect(iv)
		}
		start += int32(len(hashList))
	}

	// Send the inventory message if there is anything to send.
	if len(invMsg.InvList) > 0 {
		invListLen := len(invMsg.InvList)
		if autoContinue && invListLen == wire.MaxBlocksPerMsg {
			// Intentionally use a copy of the final hash so there
			// is not a reference into the inventory slice which
			// would prevent the entire slice from being eligible
			// for GC as soon as it's sent.
			continueHash := invMsg.InvList[invListLen-1].Hash
			pInfo, err := s.blockManager.peerInfo(p)
			if err != nil {
				bmgrLog.Errorf("%v", err)
				return
			}
			pInfo.continueHash = &continueHash
		}
		p.QueueMessage(invMsg, nil)
	}
}

// handleGetHeadersMsg is invoked when a peer receives a getheaders bitcoin
// message.
func (s *server) handleGetHeadersMsg(p *peer.Peer, msg *wire.MsgGetHeaders) {
	// Attempt to look up the height of the provided stop hash.
	endIdx := database.AllShas
	height, err := s.db.FetchBlockHeightBySha(&msg.HashStop)
	if err == nil {
		endIdx = height + 1
	}

	// There are no block locators so a specific header is being requested
	// as identified by the stop hash.
	if len(msg.BlockLocatorHashes) == 0 {
		// No blocks with the stop hash were found so there is nothing
		// to do.  Just return.  This behavior mirrors the reference
		// implementation.
		if endIdx == database.AllShas {
			return
		}

		// Fetch and send the requested block header.
		header, err := s.db.FetchBlockHeaderBySha(&msg.HashStop)
		if err != nil {
			peerLog.Warnf("Lookup of known block hash failed: %v",
				err)
			return
		}

		headersMsg := wire.NewMsgHeaders()
		headersMsg.AddBlockHeader(header)
		p.QueueMessage(headersMsg, nil)
		return
	}

	// Find the most recent known block based on the block locator.
	// Use the block after the genesis block if no other blocks in the
	// provided locator are known.  This does mean the client will start
	// over with the genesis block if unknown block locators are provided.
	// This mirrors the behavior in the reference implementation.
	startIdx := int32(1)
	for _, hash := range msg.BlockLocatorHashes {
		height, err := s.db.FetchBlockHeightBySha(hash)
		if err == nil {
			// Start with the next hash since we know this one.
			startIdx = height + 1
			break
		}
	}

	// Don't attempt to fetch more than we can put into a single message.
	if endIdx-startIdx > wire.MaxBlockHeadersPerMsg {
		endIdx = startIdx + wire.MaxBlockHeadersPerMsg
	}

	// Generate headers message and send it.
	//
	// The FetchHeightRange call is limited to a maximum number of hashes
	// per invocation.  Since the maximum number of headers per message
	// might be larger, call it multiple times with the appropriate indices
	// as needed.
	headersMsg := wire.NewMsgHeaders()
	for start := startIdx; start < endIdx; {
		// Fetch the inventory from the block database.
		hashList, err := s.db.FetchHeightRange(start, endIdx)
		if err != nil {
			peerLog.Warnf("Header lookup failed: %v", err)
			return
		}

		// The database did not return any further hashes.  Break out of
		// the loop now.
		if len(hashList) == 0 {
			break
		}

		// Add headers to the message.
		for _, hash := range hashList {
			header, err := s.db.FetchBlockHeaderBySha(&hash)
			if err != nil {
				peerLog.Warnf("Lookup of known block hash "+
					"failed: %v", err)
				continue
			}
			headersMsg.AddBlockHeader(header)
		}

		// Start at the next block header after the latest one on the
		// next loop iteration.
		start += int32(len(hashList))
	}
	p.QueueMessage(headersMsg, nil)
}

// isValidBIP0111 is a helper function for the bloom filter commands to check
// BIP0111 compliance.
func isValidBIP0111(p *peer.Peer, cmd string) bool {
	if p.Services()&wire.SFNodeBloom != wire.SFNodeBloom {
		if p.ProtocolVersion() >= wire.BIP0111Version {
			peerLog.Debugf("%s sent an unsupported %s "+
				"request -- disconnecting", p, cmd)
			p.Disconnect()
		} else {
			peerLog.Debugf("Ignoring %s request from %s -- bloom "+
				"support is disabled", cmd, p)
		}
		return false
	}

	return true
}

// handleFilterAddMsg is invoked when a peer receives a filteradd bitcoin
// message and is used by remote peers to add data to an already loaded bloom
// filter.  The peer will be disconnected if a filter is not loaded when this
// message is received.
func (s *server) handleFilterAddMsg(p *peer.Peer, msg *wire.MsgFilterAdd) {
	if !isValidBIP0111(p, msg.Command()) {
		return
	}

	pInfo, err := s.blockManager.peerInfo(p)
	if err != nil {
		bmgrLog.Errorf("%v", err)
		return
	}
	if pInfo.filter.IsLoaded() {
		peerLog.Debugf("%s sent a filteradd request with no filter "+
			"loaded -- disconnecting", p)
		p.Disconnect()
		return
	}

	pInfo.filter.Add(msg.Data)
}

// handleFilterClearMsg is invoked when a peer receives a filterclear bitcoin
// message and is used by remote peers to clear an already loaded bloom filter.
// The peer will be disconnected if a filter is not loaded when this message is
// received.
func (s *server) handleFilterClearMsg(p *peer.Peer, msg *wire.MsgFilterClear) {
	if !isValidBIP0111(p, msg.Command()) {
		return
	}

	pInfo, err := s.blockManager.peerInfo(p)
	if err != nil {
		bmgrLog.Errorf("%v", err)
		return
	}
	if !pInfo.filter.IsLoaded() {
		peerLog.Debugf("%s sent a filterclear request with no "+
			"filter loaded -- disconnecting", p)
		p.Disconnect()
		return
	}
	pInfo.filter.Unload()
}

// handleFilterLoadMsg is invoked when a peer receives a filterload bitcoin
// message and it used to load a bloom filter that should be used for
// delivering merkle blocks and associated transactions that match the filter.
func (s *server) handleFilterLoadMsg(p *peer.Peer, msg *wire.MsgFilterLoad) {
	if !isValidBIP0111(p, msg.Command()) {
		return
	}

	pInfo, err := s.blockManager.peerInfo(p)
	if err != nil {
		bmgrLog.Errorf("%v", err)
		return
	}
	pInfo.relayMtx.Lock()
	pInfo.disableRelayTx = false
	pInfo.relayMtx.Unlock()

	pInfo.filter.Reload(msg)
}

// handleGetAddrMsg is invoked when a peer receives a getaddr bitcoin message
// and is used to provide the peer with known addresses from the address
// manager.
func (s *server) handleGetAddrMsg(p *peer.Peer, msg *wire.MsgGetAddr) {
	// Don't return any addresses when running on the simulation test
	// network.  This helps prevent the network from becoming another
	// public test network since it will not be able to learn about other
	// peers that have not specifically been provided.
	if cfg.SimNet {
		return
	}

	// Do not accept getaddr requests from outbound peers.  This reduces
	// fingerprinting attacks.
	if !p.Inbound() {
		return
	}

	// Get the current known addresses from the address manager.
	addrCache := s.addrManager.AddressCache()

	pInfo, err := s.blockManager.peerInfo(p)
	if err != nil {
		bmgrLog.Errorf("%v", err)
		return
	}
	var addresses []*wire.NetAddress
	// Filter addresses the peer already knows about.
	for _, na := range addrCache {
		if !pInfo.addressKnown(addrmgr.NetAddressKey(na)) {
			addresses = append(addresses, na)
		}
	}

	// Push the addresses.
	err = p.PushAddrMsg(addresses)
	if err != nil {
		peerLog.Errorf("Can't push address message to %s: %v", p, err)
		p.Disconnect()
		return
	}

	// Add addresses known for this peer.
	for _, na := range addresses {
		pInfo.addKnownAddress(addrmgr.NetAddressKey(na))
	}
}

// handleAddrMsg is invoked when a peer receives an addr bitcoin message and is
// used to notify the server about advertised addresses.
func (s *server) handleAddrMsg(p *peer.Peer, msg *wire.MsgAddr) {
	// Ignore addresses when running on the simulation test network.  This
	// helps prevent the network from becoming another public test network
	// since it will not be able to learn about other peers that have not
	// specifically been provided.
	if cfg.SimNet {
		return
	}

	// Ignore old style addresses which don't include a timestamp.
	if p.ProtocolVersion() < wire.NetAddressTimeVersion {
		return
	}

	// A message that has no addresses is invalid.
	if len(msg.AddrList) == 0 {
		peerLog.Errorf("Command [%s] from %s does not contain any addresses",
			msg.Command(), p)
		p.Disconnect()
		return
	}

	for _, na := range msg.AddrList {
		// Don't add more address if we're disconnecting.
		if !p.Connected() {
			return
		}

		// Set the timestamp to 5 days ago if it's more than 24 hours
		// in the future so this address is one of the first to be
		// removed when space is needed.
		now := time.Now()
		if na.Timestamp.After(now.Add(time.Minute * 10)) {
			na.Timestamp = now.Add(-1 * time.Hour * 24 * 5)
		}

		// Add address to known addresses for this peer.
		pInfo, err := s.blockManager.peerInfo(p)
		if err != nil {
			bmgrLog.Errorf("%v", err)
			return
		}
		pInfo.addKnownAddress(addrmgr.NetAddressKey(na))
	}

	// Add addresses to server address manager.  The address manager handles
	// the details of things such as preventing duplicate addresses, max
	// addresses, and last seen updates.
	// XXX bitcoind gives a 2 hour time penalty here, do we want to do the
	// same?
	s.addrManager.AddAddresses(msg.AddrList, p.NA())
}

// registerListeners registers peer message listeners
func (s *server) registerListeners(p *peer.Peer) {
	p.AddVersionMsgListener("handleVersionMsg", s.handleVersionMsg)
	p.AddMemPoolMsgListener("handleMemPoolMsg", s.handleMemPoolMsg)
	p.AddTxMsgListener("handleTxMsg", s.handleTxMsg)
	p.AddBlockMsgListener("handleBlockMsg", s.handleBlockMsg)
	p.AddInvMsgListener("handleInvMsg", s.handleInvMsg)
	p.AddHeadersMsgListener("handleHeadersMsg", s.handleHeadersMsg)
	p.AddGetDataMsgListener("handleGetDataMsg", s.handleGetDataMsg)
	p.AddGetBlocksMsgListener("handleGetBlocksMsg", s.handleGetBlocksMsg)
	p.AddGetHeadersMsgListener("handleGetHeadersMsg", s.handleGetHeadersMsg)
	p.AddFilterAddMsgListener("handleFilterAddMsg", s.handleFilterAddMsg)
	p.AddFilterClearMsgListener("handleFilterClearMsg", s.handleFilterClearMsg)
	p.AddFilterLoadMsgListener("handleFilterLoadMsg", s.handleFilterLoadMsg)
	p.AddGetAddrMsgListener("handleGetAddrMsg", s.handleGetAddrMsg)
	p.AddAddrMsgListener("handleAddrMsg", s.handleAddrMsg)

	// When peer gets shutdown, notify the server that it is done.
	go func() {
		p.WaitForShutdown()
		s.donePeers <- p

		// Only tell block manager we are gone if we ever told it we existed.
		if p.VersionKnown() {
			s.blockManager.DonePeer(p)
		}
	}()
}

func (p *peerState) Count() int {
	return len(p.peers) + len(p.outboundPeers) + len(p.persistentPeers)
}

func (p *peerState) OutboundCount() int {
	return len(p.outboundPeers) + len(p.persistentPeers)
}

func (p *peerState) NeedMoreOutbound() bool {
	return p.OutboundCount() < p.maxOutboundPeers &&
		p.Count() < cfg.MaxPeers
}

// forAllOutboundPeers is a helper function that runs closure on all outbound
// peers known to peerState.
func (p *peerState) forAllOutboundPeers(closure func(p *peer.Peer)) {
	for e := range p.outboundPeers {
		closure(e)
	}
	for e := range p.persistentPeers {
		closure(e)
	}
}

// forAllPeers is a helper function that runs closure on all peers known to
// peerState.
func (p *peerState) forAllPeers(closure func(p *peer.Peer)) {
	for e := range p.peers {
		closure(e)
	}
	p.forAllOutboundPeers(closure)
}

// handleUpdatePeerHeight updates the heights of all peers who were known to
// announce a block we recently accepted.
func (s *server) handleUpdatePeerHeights(state *peerState, umsg updatePeerHeightsMsg) {
	state.forAllPeers(func(p *peer.Peer) {
		// The origin peer should already have the updated height.
		if p == umsg.originPeer {
			return
		}

		// This is a pointer to the underlying memory which doesn't
		// change.
		latestBlkSha := p.LastAnnouncedBlock()

		// Skip this peer if it hasn't recently announced any new blocks.
		if latestBlkSha == nil {
			return
		}

		// If the peer has recently announced a block, and this block
		// matches our newly accepted block, then update their block
		// height.
		if *latestBlkSha == *umsg.newSha {
			p.UpdateLastBlockHeight(umsg.newHeight)
			p.UpdateLastAnnouncedBlock(nil)
		}
	})
}

// handleAddPeerMsg deals with adding new peers.  It is invoked from the
// peerHandler goroutine.
func (s *server) handleAddPeerMsg(state *peerState, p *peer.Peer, persistent bool) bool {
	if p == nil {
		return false
	}

	// Ignore new peers if we're shutting down.
	if atomic.LoadInt32(&s.shutdown) != 0 {
		srvrLog.Infof("New peer %s ignored - server is shutting "+
			"down", p)
		p.Shutdown()
		return false
	}

	// Disconnect banned peers.
	host, _, err := net.SplitHostPort(p.Addr())
	if err != nil {
		srvrLog.Debugf("can't split hostport %v", err)
		p.Shutdown()
		return false
	}
	if banEnd, ok := state.banned[host]; ok {
		if time.Now().Before(banEnd) {
			srvrLog.Debugf("Peer %s is banned for another %v - "+
				"disconnecting", host, banEnd.Sub(time.Now()))
			p.Shutdown()
			return false
		}

		srvrLog.Infof("Peer %s is no longer banned", host)
		delete(state.banned, host)
	}

	// TODO: Check for max peers from a single IP.

	// Limit max number of total peers.
	if state.Count() >= cfg.MaxPeers {
		srvrLog.Infof("Max peers reached [%d] - disconnecting "+
			"peer %s", cfg.MaxPeers, p)
		p.Shutdown()
		// TODO(oga) how to handle permanent peers here?
		// they should be rescheduled.
		return false
	}

	// Add the new peer and start it.
	srvrLog.Debugf("New peer %s", p)
	if p.Inbound() {
		state.peers[p] = struct{}{}
		p.Start()
	} else {
		state.outboundGroups[addrmgr.GroupKey(p.NA())]++
		if persistent {
			state.persistentPeers[p] = struct{}{}
		} else {
			state.outboundPeers[p] = struct{}{}
		}
	}

	return true
}

// handleDonePeerMsg deals with peers that have signalled they are done.  It is
// invoked from the peerHandler goroutine.
func (s *server) handleDonePeerMsg(state *peerState, p *peer.Peer) {
	var list map[*peer.Peer]struct{}
	var persistent bool
	if _, ok := state.persistentPeers[p]; ok {
		list = state.persistentPeers
		persistent = true
	} else if p.Inbound() {
		list = state.peers
	} else {
		list = state.outboundPeers
	}
	for e := range list {
		if e == p {
			// Issue an asynchronous reconnect if the peer was a
			// persistent outbound connection.
			if !p.Inbound() && persistent && atomic.LoadInt32(&s.shutdown) == 0 {
				// Retry peer
				p = s.addPeer(p.Addr())
				if p != nil {
					go s.retryConn(p, connectionRetryInterval/2)
					s.handleAddPeerMsg(state, p, true)
				}
				return
			}
			if !p.Inbound() {
				state.outboundGroups[addrmgr.GroupKey(p.NA())]--
			}
			delete(list, e)
			srvrLog.Debugf("Removed peer %s", p)
			return
		}
	}
	// Update the address' last seen time if the peer has acknowledged
	// our version and has sent us its version as well.
	if p.VerAckReceived() && p.VersionKnown() && p.NA() != nil {
		s.addrManager.Connected(p.NA())
	}

	// If we get here it means that either we didn't know about the peer
	// or we purposefully deleted it.
}

// handleBanPeerMsg deals with banning peers.  It is invoked from the
// peerHandler goroutine.
func (s *server) handleBanPeerMsg(state *peerState, p *peer.Peer) {
	host, _, err := net.SplitHostPort(p.Addr())
	if err != nil {
		srvrLog.Debugf("can't split ban peer %s %v", p.Addr(), err)
		return
	}
	direction := directionString(p.Inbound())
	srvrLog.Infof("Banned peer %s (%s) for %v", host, direction,
		cfg.BanDuration)
	state.banned[host] = time.Now().Add(cfg.BanDuration)

}

// handleRelayInvMsg deals with relaying inventory to peers that are not already
// known to have it.  It is invoked from the peerHandler goroutine.
func (s *server) handleRelayInvMsg(state *peerState, msg relayMsg) {
	state.forAllPeers(func(p *peer.Peer) {
		if !p.Connected() {
			return
		}

		if msg.invVect.Type == wire.InvTypeTx {
			pInfo, err := s.blockManager.peerInfo(p)
			if err != nil {
				bmgrLog.Errorf("%v", err)
				return
			}
			// Don't relay the transaction to the peer when it has
			// transaction relaying disabled.
			if pInfo.relayTxDisabled() {
				return
			}
			// Don't relay the transaction if there is a bloom
			// filter loaded and the transaction doesn't match it.
			if pInfo.filter.IsLoaded() {
				tx, ok := msg.data.(*btcutil.Tx)
				if !ok {
					peerLog.Warnf("Underlying data for tx" +
						" inv relay is not a transaction")
					return
				}

				if !pInfo.filter.MatchTxAndUpdate(tx) {
					return
				}
			}
		}

		// Queue the inventory to be relayed with the next batch.
		// It will be ignored if the peer is already known to
		// have the inventory.
		p.QueueInventory(msg.invVect)
	})
}

// handleBroadcastMsg deals with broadcasting messages to peers.  It is invoked
// from the peerHandler goroutine.
func (s *server) handleBroadcastMsg(state *peerState, bmsg *broadcastMsg) {
	state.forAllPeers(func(p *peer.Peer) {
		excluded := false
		for _, ep := range bmsg.excludePeers {
			if p == ep {
				excluded = true
			}
		}
		// Don't broadcast to still connecting outbound peers .
		if !p.Connected() {
			excluded = true
		}
		if !excluded {
			p.QueueMessage(bmsg.message, nil)
		}
	})
}

type getConnCountMsg struct {
	reply chan int32
}

type getPeersMsg struct {
	reply chan []*peer.Peer
}

type getAddedNodesMsg struct {
	reply chan []*peer.Peer
}

type disconnectNodeMsg struct {
	cmp   func(*peer.Peer) bool
	reply chan error
}

type connectNodeMsg struct {
	addr      string
	permanent bool
	reply     chan error
}

type removeNodeMsg struct {
	cmp   func(*peer.Peer) bool
	reply chan error
}

// handleQuery is the central handler for all queries and commands from other
// goroutines related to peer state.
func (s *server) handleQuery(querymsg interface{}, state *peerState) {
	switch msg := querymsg.(type) {
	case getConnCountMsg:
		nconnected := int32(0)
		state.forAllPeers(func(p *peer.Peer) {
			if p.Connected() {
				nconnected++
			}
		})
		msg.reply <- nconnected

	case getPeersMsg:
		peers := make([]*peer.Peer, len(state.peers))
		state.forAllPeers(func(p *peer.Peer) {
			if !p.Connected() {
				return
			}
			peers = append(peers, p)
		})
		msg.reply <- peers

	case connectNodeMsg:
		// XXX(oga) duplicate oneshots?
		for peer := range state.persistentPeers {
			if peer.Addr() == msg.addr {
				if msg.permanent {
					msg.reply <- errors.New("peer already connected")
				} else {
					msg.reply <- errors.New("peer exists as a permanent peer")
				}
				return
			}
		}

		// TODO(oga) if too many, nuke a non-perm peer.
		p := s.addPeer(msg.addr)
		if p != nil && s.handleAddPeerMsg(state, p, msg.permanent) {
			msg.reply <- nil
		} else {
			msg.reply <- errors.New("failed to add peer")
		}
		go s.establishConn(p)
	case removeNodeMsg:
		found := disconnectPeer(state.persistentPeers, msg.cmp, func(p *peer.Peer) {
			// Keep group counts ok since we remove from
			// the list now.
			state.outboundGroups[addrmgr.GroupKey(p.NA())]--
		})

		if found {
			msg.reply <- nil
		} else {
			msg.reply <- errors.New("peer not found")
		}
	// Request a list of the persistent (added) peers.
	case getAddedNodesMsg:
		// Respond with a slice of the relavent peers.
		peers := make([]*peer.Peer, 0, len(state.persistentPeers))
		for peer := range state.persistentPeers {
			peers = append(peers, peer)
		}
		msg.reply <- peers
	case disconnectNodeMsg:
		// Check inbound peers. We pass a nil callback since we don't
		// require any additional actions on disconnect for inbound peers.
		found := disconnectPeer(state.peers, msg.cmp, nil)
		if found {
			msg.reply <- nil
			return
		}

		// Check outbound peers.
		found = disconnectPeer(state.outboundPeers, msg.cmp, func(p *peer.Peer) {
			// Keep group counts ok since we remove from
			// the list now.
			state.outboundGroups[addrmgr.GroupKey(p.NA())]--
		})
		if found {
			// If there are multiple outbound connections to the same
			// ip:port, continue disconnecting them all until no such
			// peers are found.
			for found {
				found = disconnectPeer(state.outboundPeers, msg.cmp, func(p *peer.Peer) {
					state.outboundGroups[addrmgr.GroupKey(p.NA())]--
				})
			}
			msg.reply <- nil
			return
		}

		msg.reply <- errors.New("peer not found")
	}
}

// disconnectPeer attempts to drop the connection of a tageted peer in the
// passed peer list. Targets are identified via usage of the passed
// `compareFunc`, which should return `true` if the passed peer is the target
// peer. This function returns true on success and false if the peer is unable
// to be located. If the peer is found, and the passed callback: `whenFound'
// isn't nil, we call it with the peer as the argument before it is removed
// from the peerList, and is disconnected from the server.
func disconnectPeer(peerList map[*peer.Peer]struct{}, compareFunc func(*peer.Peer) bool, whenFound func(*peer.Peer)) bool {
	for peer := range peerList {
		if compareFunc(peer) {
			if whenFound != nil {
				whenFound(peer)
			}

			// This is ok because we are not continuing
			// to iterate so won't corrupt the loop.
			delete(peerList, peer)
			peer.Disconnect()
			return true
		}
	}
	return false
}

// listenHandler is the main listener which accepts incoming connections for the
// server.  It must be run as a goroutine.
func (s *server) listenHandler(listener net.Listener) {
	srvrLog.Infof("Server listening on %s", listener.Addr())
	for atomic.LoadInt32(&s.shutdown) == 0 {
		conn, err := listener.Accept()
		if err != nil {
			// Only log the error if we're not forcibly shutting down.
			if atomic.LoadInt32(&s.shutdown) == 0 {
				srvrLog.Errorf("can't accept connection: %v",
					err)
			}
			continue
		}
		peerCfg := &peer.Config{
			NewestBlock:      s.db.NewestSha,
			BestLocalAddress: s.addrManager.GetBestLocalAddress,
			Proxy:            cfg.Proxy,
			RegressionTest:   cfg.RegressionTest,
			UserAgentName:    userAgentName,
			UserAgentVersion: userAgentVersion,
			Net:              s.chainParams.Net,
			Services:         wire.SFNodeNetwork,
		}
		p := peer.NewInboundPeer(peerCfg, s.nonce, conn)
		s.registerListeners(p)
		s.AddPeer(p)
	}
	s.wg.Done()
	srvrLog.Tracef("Listener handler done for %s", listener.Addr())
}

// seedFromDNS uses DNS seeding to populate the address manager with peers.
func (s *server) seedFromDNS() {
	// Nothing to do if DNS seeding is disabled.
	if cfg.DisableDNSSeed {
		return
	}

	for _, seeder := range activeNetParams.dnsSeeds {
		go func(seeder string) {
			randSource := mrand.New(mrand.NewSource(time.Now().UnixNano()))

			seedpeers, err := dnsDiscover(seeder)
			if err != nil {
				discLog.Infof("DNS discovery failed on seed %s: %v", seeder, err)
				return
			}
			numPeers := len(seedpeers)

			discLog.Infof("%d addresses found from DNS seed %s", numPeers, seeder)

			if numPeers == 0 {
				return
			}
			addresses := make([]*wire.NetAddress, len(seedpeers))
			// if this errors then we have *real* problems
			intPort, _ := strconv.Atoi(activeNetParams.DefaultPort)
			for i, peer := range seedpeers {
				addresses[i] = new(wire.NetAddress)
				addresses[i].SetAddress(peer, uint16(intPort))
				// bitcoind seeds with addresses from
				// a time randomly selected between 3
				// and 7 days ago.
				addresses[i].Timestamp = time.Now().Add(-1 *
					time.Second * time.Duration(secondsIn3Days+
					randSource.Int31n(secondsIn4Days)))
			}

			// Bitcoind uses a lookup of the dns seeder here. This
			// is rather strange since the values looked up by the
			// DNS seed lookups will vary quite a lot.
			// to replicate this behaviour we put all addresses as
			// having come from the first one.
			s.addrManager.AddAddresses(addresses, addresses[0])
		}(seeder)
	}
}

// addPeer initializes a new outbound peer and setups the message listeners.
func (s *server) addPeer(addr string) *peer.Peer {
	peerCfg := &peer.Config{
		NewestBlock:      s.db.NewestSha,
		BestLocalAddress: s.addrManager.GetBestLocalAddress,
		Proxy:            cfg.Proxy,
		RegressionTest:   cfg.RegressionTest,
		UserAgentName:    userAgentName,
		UserAgentVersion: userAgentVersion,
		Net:              s.chainParams.Net,
		Services:         wire.SFNodeNetwork,
	}
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		srvrLog.Errorf("Tried to create a new outbound peer with invalid "+
			"address %s: %v", addr, err)
		return nil
	}

	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		srvrLog.Errorf("Tried to create a new outbound peer with invalid "+
			"port %s: %v", portStr, err)
		return nil
	}

	na, err := s.addrManager.HostToNetAddress(host, uint16(port), peerCfg.Services)
	if err != nil {
		srvrLog.Errorf("Can not turn host %s into netaddress: %v",
			host, err)
		return nil
	}

	p := peer.NewOutboundPeer(peerCfg, s.nonce, na)
	s.registerListeners(p)
	return p
}

// establishConn establishes a connection to the peer.
func (s *server) establishConn(p *peer.Peer) error {
	conn, err := btcdDial("tcp", p.Addr())
	if err != nil {
		return err
	}
	if err := p.Connect(conn); err != nil {
		return err
	}
	s.addrManager.Attempt(p.NA())
	return nil
}

// retryConn retries connection to the peer after the given duration.
func (s *server) retryConn(p *peer.Peer, retryDuration time.Duration) {
	srvrLog.Debugf("Retrying connection to %s in %s", p.Addr(), retryDuration)
	select {
	case <-time.After(retryDuration):
		err := s.establishConn(p)
		if err != nil {
			srvrLog.Debugf("Failed to connect to %s: %v", p.Addr(), err)
			retryDuration += connectionRetryInterval / 2
			if retryDuration > maxConnectionRetryInterval {
				retryDuration = maxConnectionRetryInterval
			}
			go s.retryConn(p, retryDuration)
			return
		}
	case <-s.quit:
	}
}

// peerHandler is used to handle peer operations such as adding and removing
// peers to and from the server, banning peers, and broadcasting messages to
// peers.  It must be run in a goroutine.
func (s *server) peerHandler() {
	// Start the address manager and block manager, both of which are needed
	// by peers.  This is done here since their lifecycle is closely tied
	// to this handler and rather than adding more channels to sychronize
	// things, it's easier and slightly faster to simply start and stop them
	// in this handler.
	s.addrManager.Start()
	s.blockManager.Start()

	srvrLog.Tracef("Starting peer handler")
	state := &peerState{
		peers:            make(map[*peer.Peer]struct{}),
		persistentPeers:  make(map[*peer.Peer]struct{}),
		outboundPeers:    make(map[*peer.Peer]struct{}),
		banned:           make(map[string]time.Time),
		maxOutboundPeers: defaultMaxOutbound,
		outboundGroups:   make(map[string]int),
	}
	if cfg.MaxPeers < state.maxOutboundPeers {
		state.maxOutboundPeers = cfg.MaxPeers
	}

	// Add peers discovered through DNS to the address manager.
	s.seedFromDNS()

	// Start up persistent peers.
	permanentPeers := cfg.ConnectPeers
	if len(permanentPeers) == 0 {
		permanentPeers = cfg.AddPeers
	}
	for _, addr := range permanentPeers {
		p := s.addPeer(addr)
		if p != nil {
			go s.establishConn(p)
			s.handleAddPeerMsg(state, p, true)
		}
	}

	// if nothing else happens, wake us up soon.
	time.AfterFunc(10*time.Second, func() { s.wakeup <- struct{}{} })

out:
	for {
		select {
		// New peers connected to the server.
		case p := <-s.newPeers:
			s.handleAddPeerMsg(state, p, true)

		// Disconnected peers.
		case p := <-s.donePeers:
			s.handleDonePeerMsg(state, p)

		// Block accepted in mainchain or orphan, update peer height.
		case umsg := <-s.peerHeightsUpdate:
			s.handleUpdatePeerHeights(state, umsg)

		// Peer to ban.
		case p := <-s.banPeers:
			s.handleBanPeerMsg(state, p)

		// New inventory to potentially be relayed to other peers.
		case invMsg := <-s.relayInv:
			s.handleRelayInvMsg(state, invMsg)

		// Message to broadcast to all connected peers except those
		// which are excluded by the message.
		case bmsg := <-s.broadcast:
			s.handleBroadcastMsg(state, &bmsg)

		// Used by timers below to wake us back up.
		case <-s.wakeup:
			// this page left intentionally blank

		case qmsg := <-s.query:
			s.handleQuery(qmsg, state)

		// Shutdown the peer handler.
		case <-s.quit:
			// Shutdown peers.
			state.forAllPeers(func(p *peer.Peer) {
				p.Shutdown()
			})
			break out
		}

		// Don't try to connect to more peers when running on the
		// simulation test network.  The simulation network is only
		// intended to connect to specified peers and actively avoid
		// advertising and connecting to discovered peers.
		if cfg.SimNet {
			continue
		}

		// Only try connect to more peers if we actually need more.
		if !state.NeedMoreOutbound() || len(cfg.ConnectPeers) > 0 ||
			atomic.LoadInt32(&s.shutdown) != 0 {
			continue
		}
		tries := 0
		for state.NeedMoreOutbound() &&
			atomic.LoadInt32(&s.shutdown) == 0 {
			nPeers := state.OutboundCount()
			if nPeers > 8 {
				nPeers = 8
			}
			addr := s.addrManager.GetAddress("any")
			if addr == nil {
				break
			}
			key := addrmgr.GroupKey(addr.NetAddress())
			// Address will not be invalid, local or unroutable
			// because addrmanager rejects those on addition.
			// Just check that we don't already have an address
			// in the same group so that we are not connecting
			// to the same network segment at the expense of
			// others.
			if state.outboundGroups[key] != 0 {
				break
			}

			tries++
			// After 100 bad tries exit the loop and we'll try again
			// later.
			if tries > 100 {
				break
			}

			// XXX if we have limited that address skip

			// only allow recent nodes (10mins) after we failed 30
			// times
			if tries < 30 && time.Now().Sub(addr.LastAttempt()) < 10*time.Minute {
				continue
			}

			// allow nondefault ports after 50 failed tries.
			if fmt.Sprintf("%d", addr.NetAddress().Port) !=
				activeNetParams.DefaultPort && tries < 50 {
				continue
			}

			addrStr := addrmgr.NetAddressKey(addr.NetAddress())

			tries = 0
			p := s.addPeer(addrStr)
			if p != nil {
				go s.establishConn(p)
				// any failure will be due to banned peers etc. we have
				// already checked that we have room for more peers.
				if s.handleAddPeerMsg(state, p, true) {
				}
			}
		}

		// We need more peers, wake up in ten seconds and try again.
		if state.NeedMoreOutbound() {
			time.AfterFunc(10*time.Second, func() {
				s.wakeup <- struct{}{}
			})
		}
	}

	if cfg.AddrIndex {
		s.addrIndexer.Stop()
	}
	s.blockManager.Stop()
	s.addrManager.Stop()
	s.wg.Done()
	srvrLog.Tracef("Peer handler done")
}

// AddPeer adds a new peer that has already been connected to the server.
func (s *server) AddPeer(p *peer.Peer) {
	s.newPeers <- p
}

// BanPeer bans a peer that has already been connected to the server by ip.
func (s *server) BanPeer(p *peer.Peer) {
	s.banPeers <- p
}

// RelayInventory relays the passed inventory to all connected peers that are
// not already known to have it.
func (s *server) RelayInventory(invVect *wire.InvVect, data interface{}) {
	s.relayInv <- relayMsg{invVect: invVect, data: data}
}

// BroadcastMessage sends msg to all peers currently connected to the server
// except those in the passed peers to exclude.
func (s *server) BroadcastMessage(msg wire.Message, exclPeers ...*peer.Peer) {
	// XXX: Need to determine if this is an alert that has already been
	// broadcast and refrain from broadcasting again.
	bmsg := broadcastMsg{message: msg, excludePeers: exclPeers}
	s.broadcast <- bmsg
}

// ConnectedCount returns the number of currently connected peers.
func (s *server) ConnectedCount() int32 {
	replyChan := make(chan int32)

	s.query <- getConnCountMsg{reply: replyChan}

	return <-replyChan
}

// AddedNodeInfo returns an array of btcjson.GetAddedNodeInfoResult structures
// describing the persistent (added) nodes.
func (s *server) AddedNodeInfo() []*peer.Peer {
	replyChan := make(chan []*peer.Peer)
	s.query <- getAddedNodesMsg{reply: replyChan}
	return <-replyChan
}

// Peers returns an array of all connected peers.
func (s *server) Peers() []*peer.Peer {
	replyChan := make(chan []*peer.Peer)

	s.query <- getPeersMsg{reply: replyChan}

	return <-replyChan
}

// DisconnectNodeByAddr disconnects a peer by target address. Both outbound and
// inbound nodes will be searched for the target node. An error message will
// be returned if the peer was not found.
func (s *server) DisconnectNodeByAddr(addr string) error {
	replyChan := make(chan error)

	s.query <- disconnectNodeMsg{
		cmp:   func(p *peer.Peer) bool { return p.Addr() == addr },
		reply: replyChan,
	}

	return <-replyChan
}

// DisconnectNodeByID disconnects a peer by target node id. Both outbound and
// inbound nodes will be searched for the target node. An error message will be
// returned if the peer was not found.
func (s *server) DisconnectNodeById(id int32) error {
	replyChan := make(chan error)

	s.query <- disconnectNodeMsg{
		cmp:   func(p *peer.Peer) bool { return p.ID() == id },
		reply: replyChan,
	}

	return <-replyChan
}

// RemoveNodeByAddr removes a peer from the list of persistent peers if
// present. An error will be returned if the peer was not found.
func (s *server) RemoveNodeByAddr(addr string) error {
	replyChan := make(chan error)

	s.query <- removeNodeMsg{
		cmp:   func(p *peer.Peer) bool { return p.Addr() == addr },
		reply: replyChan,
	}

	return <-replyChan
}

// RemoveNodeById removes a peer by node ID from the list of persistent peers
// if present. An error will be returned if the peer was not found.
func (s *server) RemoveNodeById(id int32) error {
	replyChan := make(chan error)

	s.query <- removeNodeMsg{
		cmp:   func(p *peer.Peer) bool { return p.ID() == id },
		reply: replyChan,
	}

	return <-replyChan
}

// ConnectNode adds `addr' as a new outbound peer. If permanent is true then the
// peer will be persistent and reconnect if the connection is lost.
// It is an error to call this with an already existing peer.
func (s *server) ConnectNode(addr string, permanent bool) error {
	replyChan := make(chan error)

	s.query <- connectNodeMsg{addr: addr, permanent: permanent, reply: replyChan}

	return <-replyChan
}

// AddBytesSent adds the passed number of bytes to the total bytes sent counter
// for the server.  It is safe for concurrent access.
func (s *server) AddBytesSent(bytesSent uint64) {
	s.bytesMutex.Lock()
	defer s.bytesMutex.Unlock()

	s.bytesSent += bytesSent
}

// AddBytesReceived adds the passed number of bytes to the total bytes received
// counter for the server.  It is safe for concurrent access.
func (s *server) AddBytesReceived(bytesReceived uint64) {
	s.bytesMutex.Lock()
	defer s.bytesMutex.Unlock()

	s.bytesReceived += bytesReceived
}

// NetTotals returns the sum of all bytes received and sent across the network
// for all peers.  It is safe for concurrent access.
func (s *server) NetTotals() (uint64, uint64) {
	s.bytesMutex.Lock()
	defer s.bytesMutex.Unlock()

	return s.bytesReceived, s.bytesSent
}

// UpdatePeerHeights updates the heights of all peers who have have announced
// the latest connected main chain block, or a recognized orphan. These height
// updates allow us to dynamically refresh peer heights, ensuring sync peer
// selection has access to the latest block heights for each peer.
func (s *server) UpdatePeerHeights(latestBlkSha *wire.ShaHash, latestHeight int32, updateSource *peer.Peer) {
	s.peerHeightsUpdate <- updatePeerHeightsMsg{
		newSha:     latestBlkSha,
		newHeight:  latestHeight,
		originPeer: updateSource,
	}
}

// rebroadcastHandler keeps track of user submitted inventories that we have
// sent out but have not yet made it into a block. We periodically rebroadcast
// them in case our peers restarted or otherwise lost track of them.
func (s *server) rebroadcastHandler() {
	// Wait 5 min before first tx rebroadcast.
	timer := time.NewTimer(5 * time.Minute)
	pendingInvs := make(map[wire.InvVect]interface{})

out:
	for {
		select {
		case riv := <-s.modifyRebroadcastInv:
			switch msg := riv.(type) {
			// Incoming InvVects are added to our map of RPC txs.
			case broadcastInventoryAdd:
				pendingInvs[*msg.invVect] = msg.data

			// When an InvVect has been added to a block, we can
			// now remove it, if it was present.
			case broadcastInventoryDel:
				if _, ok := pendingInvs[*msg]; ok {
					delete(pendingInvs, *msg)
				}
			}

		case <-timer.C:
			// Any inventory we have has not made it into a block
			// yet. We periodically resubmit them until they have.
			for iv, data := range pendingInvs {
				ivCopy := iv
				s.RelayInventory(&ivCopy, data)
			}

			// Process at a random time up to 30mins (in seconds)
			// in the future.
			timer.Reset(time.Second *
				time.Duration(randomUint16Number(1800)))

		case <-s.quit:
			break out
		}
	}

	timer.Stop()

	// Drain channels before exiting so nothing is left waiting around
	// to send.
cleanup:
	for {
		select {
		case <-s.modifyRebroadcastInv:
		default:
			break cleanup
		}
	}
	s.wg.Done()
}

// Start begins accepting connections from peers.
func (s *server) Start() {
	// Already started?
	if atomic.AddInt32(&s.started, 1) != 1 {
		return
	}

	srvrLog.Trace("Starting server")

	// Start all the listeners.  There will not be any if listening is
	// disabled.
	for _, listener := range s.listeners {
		s.wg.Add(1)
		go s.listenHandler(listener)
	}

	// Start the peer handler which in turn starts the address and block
	// managers.
	s.wg.Add(1)
	go s.peerHandler()

	if s.nat != nil {
		s.wg.Add(1)
		go s.upnpUpdateThread()
	}

	if !cfg.DisableRPC {
		s.wg.Add(1)

		// Start the rebroadcastHandler, which ensures user tx received by
		// the RPC server are rebroadcast until being included in a block.
		go s.rebroadcastHandler()

		s.rpcServer.Start()
	}

	// Start the CPU miner if generation is enabled.
	if cfg.Generate {
		s.cpuMiner.Start()
	}

	if cfg.AddrIndex {
		s.addrIndexer.Start()
	}
}

// Stop gracefully shuts down the server by stopping and disconnecting all
// peers and the main listener.
func (s *server) Stop() error {
	// Make sure this only happens once.
	if atomic.AddInt32(&s.shutdown, 1) != 1 {
		srvrLog.Infof("Server is already in the process of shutting down")
		return nil
	}

	srvrLog.Warnf("Server shutting down")

	// Stop all the listeners.  There will not be any listeners if
	// listening is disabled.
	for _, listener := range s.listeners {
		err := listener.Close()
		if err != nil {
			return err
		}
	}

	// Stop the CPU miner if needed
	s.cpuMiner.Stop()

	// Shutdown the RPC server if it's not disabled.
	if !cfg.DisableRPC {
		s.rpcServer.Stop()
	}

	// Signal the remaining goroutines to quit.
	close(s.quit)
	return nil
}

// WaitForShutdown blocks until the main listener and peer handlers are stopped.
func (s *server) WaitForShutdown() {
	s.wg.Wait()
}

// ScheduleShutdown schedules a server shutdown after the specified duration.
// It also dynamically adjusts how often to warn the server is going down based
// on remaining duration.
func (s *server) ScheduleShutdown(duration time.Duration) {
	// Don't schedule shutdown more than once.
	if atomic.AddInt32(&s.shutdownSched, 1) != 1 {
		return
	}
	srvrLog.Warnf("Server shutdown in %v", duration)
	go func() {
		remaining := duration
		tickDuration := dynamicTickDuration(remaining)
		done := time.After(remaining)
		ticker := time.NewTicker(tickDuration)
	out:
		for {
			select {
			case <-done:
				ticker.Stop()
				s.Stop()
				break out
			case <-ticker.C:
				remaining = remaining - tickDuration
				if remaining < time.Second {
					continue
				}

				// Change tick duration dynamically based on remaining time.
				newDuration := dynamicTickDuration(remaining)
				if tickDuration != newDuration {
					tickDuration = newDuration
					ticker.Stop()
					ticker = time.NewTicker(tickDuration)
				}
				srvrLog.Warnf("Server shutdown in %v", remaining)
			}
		}
	}()
}

// parseListeners splits the list of listen addresses passed in addrs into
// IPv4 and IPv6 slices and returns them.  This allows easy creation of the
// listeners on the correct interface "tcp4" and "tcp6".  It also properly
// detects addresses which apply to "all interfaces" and adds the address to
// both slices.
func parseListeners(addrs []string) ([]string, []string, bool, error) {
	ipv4ListenAddrs := make([]string, 0, len(addrs)*2)
	ipv6ListenAddrs := make([]string, 0, len(addrs)*2)
	haveWildcard := false

	for _, addr := range addrs {
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			// Shouldn't happen due to already being normalized.
			return nil, nil, false, err
		}

		// Empty host or host of * on plan9 is both IPv4 and IPv6.
		if host == "" || (host == "*" && runtime.GOOS == "plan9") {
			ipv4ListenAddrs = append(ipv4ListenAddrs, addr)
			ipv6ListenAddrs = append(ipv6ListenAddrs, addr)
			haveWildcard = true
			continue
		}

		// Parse the IP.
		ip := net.ParseIP(host)
		if ip == nil {
			return nil, nil, false, fmt.Errorf("'%s' is not a "+
				"valid IP address", host)
		}

		// To4 returns nil when the IP is not an IPv4 address, so use
		// this determine the address type.
		if ip.To4() == nil {
			ipv6ListenAddrs = append(ipv6ListenAddrs, addr)
		} else {
			ipv4ListenAddrs = append(ipv4ListenAddrs, addr)
		}
	}
	return ipv4ListenAddrs, ipv6ListenAddrs, haveWildcard, nil
}

func (s *server) upnpUpdateThread() {
	// Go off immediately to prevent code duplication, thereafter we renew
	// lease every 15 minutes.
	timer := time.NewTimer(0 * time.Second)
	lport, _ := strconv.ParseInt(activeNetParams.DefaultPort, 10, 16)
	first := true
out:
	for {
		select {
		case <-timer.C:
			// TODO(oga) pick external port  more cleverly
			// TODO(oga) know which ports we are listening to on an external net.
			// TODO(oga) if specific listen port doesn't work then ask for wildcard
			// listen port?
			// XXX this assumes timeout is in seconds.
			listenPort, err := s.nat.AddPortMapping("tcp", int(lport), int(lport),
				"btcd listen port", 20*60)
			if err != nil {
				srvrLog.Warnf("can't add UPnP port mapping: %v", err)
			}
			if first && err == nil {
				// TODO(oga): look this up periodically to see if upnp domain changed
				// and so did ip.
				externalip, err := s.nat.GetExternalAddress()
				if err != nil {
					srvrLog.Warnf("UPnP can't get external address: %v", err)
					continue out
				}
				na := wire.NewNetAddressIPPort(externalip, uint16(listenPort),
					s.services)
				err = s.addrManager.AddLocalAddress(na, addrmgr.UpnpPrio)
				if err != nil {
					// XXX DeletePortMapping?
				}
				srvrLog.Warnf("Successfully bound via UPnP to %s", addrmgr.NetAddressKey(na))
				first = false
			}
			timer.Reset(time.Minute * 15)
		case <-s.quit:
			break out
		}
	}

	timer.Stop()

	if err := s.nat.DeletePortMapping("tcp", int(lport), int(lport)); err != nil {
		srvrLog.Warnf("unable to remove UPnP port mapping: %v", err)
	} else {
		srvrLog.Debugf("succesfully disestablished UPnP port mapping")
	}

	s.wg.Done()
}

// newServer returns a new btcd server configured to listen on addr for the
// bitcoin network type specified by chainParams.  Use start to begin accepting
// connections from peers.
func newServer(listenAddrs []string, db database.Db, chainParams *chaincfg.Params) (*server, error) {
	nonce, err := wire.RandomUint64()
	if err != nil {
		return nil, err
	}

	services := defaultServices
	if cfg.NoPeerBloomFilters {
		services &^= wire.SFNodeBloom
	}

	amgr := addrmgr.New(cfg.DataDir, btcdLookup)

	var listeners []net.Listener
	var nat NAT
	if !cfg.DisableListen {
		ipv4Addrs, ipv6Addrs, wildcard, err :=
			parseListeners(listenAddrs)
		if err != nil {
			return nil, err
		}
		listeners = make([]net.Listener, 0, len(ipv4Addrs)+len(ipv6Addrs))
		discover := true
		if len(cfg.ExternalIPs) != 0 {
			discover = false
			// if this fails we have real issues.
			port, _ := strconv.ParseUint(
				activeNetParams.DefaultPort, 10, 16)

			for _, sip := range cfg.ExternalIPs {
				eport := uint16(port)
				host, portstr, err := net.SplitHostPort(sip)
				if err != nil {
					// no port, use default.
					host = sip
				} else {
					port, err := strconv.ParseUint(
						portstr, 10, 16)
					if err != nil {
						srvrLog.Warnf("Can not parse "+
							"port from %s for "+
							"externalip: %v", sip,
							err)
						continue
					}
					eport = uint16(port)
				}
				na, err := amgr.HostToNetAddress(host, eport,
					services)
				if err != nil {
					srvrLog.Warnf("Not adding %s as "+
						"externalip: %v", sip, err)
					continue
				}

				err = amgr.AddLocalAddress(na, addrmgr.ManualPrio)
				if err != nil {
					amgrLog.Warnf("Skipping specified external IP: %v", err)
				}
			}
		} else if discover && cfg.Upnp {
			nat, err = Discover()
			if err != nil {
				srvrLog.Warnf("Can't discover upnp: %v", err)
			}
			// nil nat here is fine, just means no upnp on network.
		}

		// TODO(oga) nonstandard port...
		if wildcard {
			port, err :=
				strconv.ParseUint(activeNetParams.DefaultPort,
					10, 16)
			if err != nil {
				// I can't think of a cleaner way to do this...
				goto nowc
			}
			addrs, err := net.InterfaceAddrs()
			for _, a := range addrs {
				ip, _, err := net.ParseCIDR(a.String())
				if err != nil {
					continue
				}
				na := wire.NewNetAddressIPPort(ip,
					uint16(port), services)
				if discover {
					err = amgr.AddLocalAddress(na, addrmgr.InterfacePrio)
					if err != nil {
						amgrLog.Debugf("Skipping local address: %v", err)
					}
				}
			}
		}
	nowc:

		for _, addr := range ipv4Addrs {
			listener, err := net.Listen("tcp4", addr)
			if err != nil {
				srvrLog.Warnf("Can't listen on %s: %v", addr,
					err)
				continue
			}
			listeners = append(listeners, listener)

			if discover {
				if na, err := amgr.DeserializeNetAddress(addr); err == nil {
					err = amgr.AddLocalAddress(na, addrmgr.BoundPrio)
					if err != nil {
						amgrLog.Warnf("Skipping bound address: %v", err)
					}
				}
			}
		}

		for _, addr := range ipv6Addrs {
			listener, err := net.Listen("tcp6", addr)
			if err != nil {
				srvrLog.Warnf("Can't listen on %s: %v", addr,
					err)
				continue
			}
			listeners = append(listeners, listener)
			if discover {
				if na, err := amgr.DeserializeNetAddress(addr); err == nil {
					err = amgr.AddLocalAddress(na, addrmgr.BoundPrio)
					if err != nil {
						amgrLog.Debugf("Skipping bound address: %v", err)
					}
				}
			}
		}

		if len(listeners) == 0 {
			return nil, errors.New("no valid listen address")
		}
	}

	s := server{
		nonce:                nonce,
		listeners:            listeners,
		chainParams:          chainParams,
		addrManager:          amgr,
		newPeers:             make(chan *peer.Peer, cfg.MaxPeers),
		donePeers:            make(chan *peer.Peer, cfg.MaxPeers),
		banPeers:             make(chan *peer.Peer, cfg.MaxPeers),
		retryPeers:           make(chan *peer.Peer, cfg.MaxPeers),
		wakeup:               make(chan struct{}),
		query:                make(chan interface{}),
		relayInv:             make(chan relayMsg, cfg.MaxPeers),
		broadcast:            make(chan broadcastMsg, cfg.MaxPeers),
		quit:                 make(chan struct{}),
		modifyRebroadcastInv: make(chan interface{}),
		peerHeightsUpdate:    make(chan updatePeerHeightsMsg),
		nat:                  nat,
		db:                   db,
		timeSource:           blockchain.NewMedianTime(),
		services:             services,
	}
	bm, err := newBlockManager(&s)
	if err != nil {
		return nil, err
	}
	s.blockManager = bm
	s.txMemPool = newTxMemPool(&s)
	s.cpuMiner = newCPUMiner(&s)

	if cfg.AddrIndex {
		ai, err := newAddrIndexer(&s)
		if err != nil {
			return nil, err
		}
		s.addrIndexer = ai
	}

	if !cfg.DisableRPC {
		s.rpcServer, err = newRPCServer(cfg.RPCListeners, &s)
		if err != nil {
			return nil, err
		}
	}

	return &s, nil
}

// dynamicTickDuration is a convenience function used to dynamically choose a
// tick duration based on remaining time.  It is primarily used during
// server shutdown to make shutdown warnings more frequent as the shutdown time
// approaches.
func dynamicTickDuration(remaining time.Duration) time.Duration {
	switch {
	case remaining <= time.Second*5:
		return time.Second
	case remaining <= time.Second*15:
		return time.Second * 5
	case remaining <= time.Minute:
		return time.Second * 15
	case remaining <= time.Minute*5:
		return time.Minute
	case remaining <= time.Minute*15:
		return time.Minute * 5
	case remaining <= time.Hour:
		return time.Minute * 15
	}
	return time.Hour
}

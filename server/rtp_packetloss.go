package server

import (
	"sync"
	"time"

	"github.com/pion/rtcp"
	"github.com/pion/rtp"
)

const nackEntryTimeout = 500 * time.Millisecond
const nackRetryInterval = 100 * time.Millisecond
const cleanUpTime = 5 * time.Minute

type nackEntry struct {
	received  time.Time // Tracks when a NACK for a seq num was sent
	lastRetry time.Time // Tracks when the last NACK retry was sent
}

type RtpPacketLossDetectorStore struct {
	sync.RWMutex
	detectors map[string]*RtpPacketLossDetector
}

func NewRtpPacketLossDetectorStore() *RtpPacketLossDetectorStore {
	return &RtpPacketLossDetectorStore{
		detectors: make(map[string]*RtpPacketLossDetector),
	}
}

func (s *RtpPacketLossDetectorStore) GetOrCreate(videoUID string, ssrc uint32) *RtpPacketLossDetector {
	s.Cleanup(cleanUpTime)
	s.Lock()
	defer s.Unlock()
	if detector, ok := s.detectors[videoUID]; ok {
		detector.lastAccessed = time.Now()
		return detector
	}
	detector := NewPacketLossDetector(ssrc)
	s.detectors[videoUID] = detector
	detector.lastAccessed = time.Now()
	return detector
}

func (s *RtpPacketLossDetectorStore) Cleanup(olderThan time.Duration) {
	s.Lock()
	defer s.Unlock()
	for videoUID, detector := range s.detectors {
		if time.Since(detector.lastAccessed) > olderThan {
			delete(s.detectors, videoUID)
		}
	}
}

type RtpPacketLossDetector struct {
	// Add fields as necessary
	lastSequenceNumber uint16
	ssrc               uint32
	initialized        bool
	pendingNacks       map[uint16]nackEntry
	lastAccessed       time.Time
}

// NewPacketLossDetector creates a new detector.
// SSRC is the SSRC of the media stream we are expecting from the sender.
func NewPacketLossDetector(ssrc uint32) *RtpPacketLossDetector {
	return &RtpPacketLossDetector{
		ssrc:         ssrc,
		pendingNacks: make(map[uint16]nackEntry),
	}
}

func (d *RtpPacketLossDetector) CheckAndRequest(p *rtp.Packet) []rtcp.Packet {
	now := time.Now()
	// If the detector is not yet initialized we just set the current packet as last seen
	// and can return as there won't be any packets that could have been lost yet.
	if !d.initialized {
		d.lastSequenceNumber = p.SequenceNumber
		d.initialized = true
		return nil
	}
	diff := p.SequenceNumber - d.lastSequenceNumber
	isOldPacket := diff == 0 || diff > 0xFFF // Handle sequence number wrap-around (approx)
	if isOldPacket {
		delete(d.pendingNacks, p.SequenceNumber)
	}
	// neckPairs hold entries which we want to request immediately
	var nackPairs []rtcp.NackPair
	// Go through pendingNacks and remove very old ones and retry if it's time
	for seq, ts := range d.pendingNacks {
		// A) Give up on very old packets.
		if now.Sub(ts.received) > nackEntryTimeout {
			delete(d.pendingNacks, seq)
			continue
		}
		// B) Re-request packets we've been waiting for.
		// We check if the time since the last NACK was sent for this seq
		// is greater than our retry interval.
		if now.Sub(ts.lastRetry) > nackRetryInterval {
			nackPairs = append(nackPairs, rtcp.NackPair{PacketID: seq})
			// IMPORTANT: Update the timestamp to reset the retry timer
			ts.lastRetry = now
			d.pendingNacks[seq] = ts
		}
	}
	if !isOldPacket {
		// If the received packet is newer than what we expect we have detected loss
		// loop through the gap and add the missing sequence numbers to pendingNacks list
		for seq := d.lastSequenceNumber + 1; seq != p.SequenceNumber; seq++ {
			// Add entry for request (immediately)
			nackPairs = append(nackPairs, rtcp.NackPair{PacketID: seq})
			// Add entry for pending so we can retry request later
			d.pendingNacks[seq] = nackEntry{
				received:  now,
				lastRetry: now,
			}
		}
		d.lastSequenceNumber = p.SequenceNumber
	}
	if len(nackPairs) > 0 {
		nack := &rtcp.TransportLayerNack{
			SenderSSRC: d.ssrc,
			MediaSSRC:  d.ssrc,
			Nacks:      nackPairs,
		}
		return []rtcp.Packet{nack}
	}
	return nil
}

const retransmissionBufferSize = 256 // Store last 256 packets

type RetransmissionBufferStore struct {
	sync.RWMutex
	buffers map[string]*RetransmissionBuffer
}

func NewRetransmissionBufferStore() *RetransmissionBufferStore {
	return &RetransmissionBufferStore{
		buffers: make(map[string]*RetransmissionBuffer),
	}
}

func (s *RetransmissionBufferStore) Cleanup(olderThan time.Duration) {
	s.Lock()
	defer s.Unlock()
	for videoUID, buf := range s.buffers {
		if time.Since(buf.lastAccessed) > olderThan {
			delete(s.buffers, videoUID)
		}
	}
}

// Create get or create method
func (s *RetransmissionBufferStore) GetOrCreate(key string) *RetransmissionBuffer {
	s.Cleanup(cleanUpTime)
	s.Lock()
	defer s.Unlock()
	if buf, ok := s.buffers[key]; ok {
		buf.lastAccessed = time.Now()
		return buf
	}

	// If not found, create a new buffer
	buf := NewRetransmissionBuffer()
	buf.lastAccessed = time.Now()
	s.buffers[key] = buf
	return buf
}

// RetransmissionBuffer holds sent RTP packets for a short time to handle NACKs.
type RetransmissionBuffer struct {
	sync.RWMutex
	buffer          map[uint16]*rtp.Packet
	sequenceNumbers []uint16 // Used to know which packet is the oldest
	// lastAccessed keeps track of when the buffer was last accessed
	lastAccessed time.Time
}

func NewRetransmissionBuffer() *RetransmissionBuffer {
	return &RetransmissionBuffer{
		buffer:          make(map[uint16]*rtp.Packet),
		sequenceNumbers: make([]uint16, 0, retransmissionBufferSize),
	}
}

// Add stores a packet in the buffer.
func (b *RetransmissionBuffer) Add(p *rtp.Packet) {
	b.Lock()
	defer b.Unlock()

	if len(b.sequenceNumbers) >= retransmissionBufferSize {
		// Buffer is full, evict the oldest packet
		oldestSeq := b.sequenceNumbers[0]
		delete(b.buffer, oldestSeq)
		b.sequenceNumbers = b.sequenceNumbers[1:]
	}

	b.buffer[p.SequenceNumber] = p
	b.sequenceNumbers = append(b.sequenceNumbers, p.SequenceNumber)
}

// Get retrieves a packet from the buffer by its sequence number.
func (b *RetransmissionBuffer) Get(seq uint16) (*rtp.Packet, bool) {
	b.RLock()
	defer b.RUnlock()
	p, ok := b.buffer[seq]
	return p, ok
}

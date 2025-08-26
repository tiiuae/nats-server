package server

import (
	"log"
	"sync"
	"time"

	"github.com/pion/rtcp"
	"github.com/pion/rtp"
)

const nackEntryTimeout = 500 * time.Millisecond
const nackRetryInterval = 100 * time.Millisecond

type nackEntry struct {
	received  time.Time // Tracks when a NACK for a seq num was sent
	lastRetry time.Time // Tracks when the last NACK retry was sent
}

type RtpPacketLossDetectorStore struct {
	detectors map[string]*RtpPacketLossDetector
}

func NewRtpPacketLossDetectorStore() *RtpPacketLossDetectorStore {
	return &RtpPacketLossDetectorStore{
		detectors: make(map[string]*RtpPacketLossDetector),
	}
}

func (s *RtpPacketLossDetectorStore) GetOrCreate(videoUID string, ssrc uint32) *RtpPacketLossDetector {
	if detector, ok := s.detectors[videoUID]; ok {
		return detector
	}
	detector := NewPacketLossDetector(ssrc)
	s.detectors[videoUID] = detector
	return detector
}

type RtpPacketLossDetector struct {
	// Add fields as necessary
	lastSequenceNumber uint16
	ssrc               uint32
	initialized        bool
	pendingNacks       map[uint16]nackEntry
}

// NewPacketLossDetector creates a new detector.
// SSRC is the SSRC of the media stream we are expecting from the sender.
func NewPacketLossDetector(ssrc uint32) *RtpPacketLossDetector {
	log.Printf("RtpPacketLossDetector: creating detector for SSRC=%d", ssrc)
	return &RtpPacketLossDetector{
		ssrc:         ssrc,
		pendingNacks: make(map[uint16]nackEntry),
	}
}

func (d *RtpPacketLossDetector) CheckAndRequest(p *rtp.Packet) []rtcp.Packet {
	now := time.Now()
	log.Printf("RtpPacketLossDetector: CheckAndRequest start SSRC=%d seq=%d ts=%d mark=%v pending=%d initialized=%v",
		d.ssrc, p.SequenceNumber, p.Timestamp, p.Marker, len(d.pendingNacks), d.initialized)
	// If the detector is not yet initialized we just set the current packet as last seen
	// and can return as there won't be any packets that could have been lost yet.
	if !d.initialized {
		log.Printf("RtpPacketLossDetector: initializing with first packet seq=%d (SSRC=%d)", p.SequenceNumber, d.ssrc)
		d.lastSequenceNumber = p.SequenceNumber
		d.initialized = true
		return nil
	}
	diff := p.SequenceNumber - d.lastSequenceNumber
	isOldPacket := diff == 0 && diff > 0xFFF // Handle sequence number wrap-around (approx)
	log.Printf("RtpPacketLossDetector: lastSeq=%d newSeq=%d diff=%d isOldPacket=%v",
		d.lastSequenceNumber, p.SequenceNumber, diff, isOldPacket)
	if isOldPacket {
		// If the received packet is older than what we expect we can remove it from the pendingNacks list
		if _, ok := d.pendingNacks[p.SequenceNumber]; ok {
			log.Printf("RtpPacketLossDetector: received old packet, clearing pending NACK for seq=%d", p.SequenceNumber)
		} else {
			log.Printf("RtpPacketLossDetector: received old/duplicate packet, no pending NACK for seq=%d", p.SequenceNumber)
		}
		delete(d.pendingNacks, p.SequenceNumber)
	}
	// neckPairs hold entries which we want to request immediately
	var nackPairs []rtcp.NackPair
	// Go through pendingNacks and remove very old ones and retry if it's time
	if len(d.pendingNacks) > 0 {
		log.Printf("RtpPacketLossDetector: scanning %d pending NACK entries", len(d.pendingNacks))
	}
	for seq, ts := range d.pendingNacks {
		// A) Give up on very old packets.
		if now.Sub(ts.received) > nackEntryTimeout {
			log.Printf("RtpPacketLossDetector: giving up on seq=%d after %s (> %s)",
				seq, now.Sub(ts.received).Truncate(time.Millisecond), nackEntryTimeout)
			delete(d.pendingNacks, seq)
			continue
		}
		// B) Re-request packets we've been waiting for.
		// We check if the time since the last NACK was sent for this seq
		// is greater than our retry interval.
		if now.Sub(ts.lastRetry) > nackRetryInterval {
			log.Printf("RtpPacketLossDetector: re-requesting NACK for seq=%d after %s (> %s)",
				seq, now.Sub(ts.lastRetry).Truncate(time.Millisecond), nackRetryInterval)
			nackPairs = append(nackPairs, rtcp.NackPair{PacketID: seq})
			// IMPORTANT: Update the timestamp to reset the retry timer
			ts.lastRetry = now
			d.pendingNacks[seq] = ts
		}
	}
	if !isOldPacket {
		// Packet is in-order or there is a gap.
		if p.SequenceNumber != d.lastSequenceNumber+1 {
			// If the received packet is newer than what we expect we have detected loss
			log.Printf("RtpPacketLossDetector: packet loss detected last=%d new=%d gap=%d",
				d.lastSequenceNumber, p.SequenceNumber, uint16(p.SequenceNumber-d.lastSequenceNumber-1))
			// loop through the gap and add the mission sequence numbers to pendingNacks list
			added := 0
			const sampleCap = 16
			sample := make([]uint16, 0, sampleCap)
			for seq := d.lastSequenceNumber + 1; seq != p.SequenceNumber; seq++ {
				// Add entry for request (immediately)
				nackPairs = append(nackPairs, rtcp.NackPair{PacketID: seq})
				// Add entry for pending so we can retry request later
				d.pendingNacks[seq] = nackEntry{
					received:  now,
					lastRetry: now,
				}
				if added < sampleCap {
					sample = append(sample, seq)
				}
				added++
			}
			if added > 0 {
				log.Printf("RtpPacketLossDetector: queued %d NACK(s) for missing seqs; sample=%v", added, sample)
			}
		}
		d.lastSequenceNumber = p.SequenceNumber
		log.Printf("RtpPacketLossDetector: updated lastSequenceNumber=%d", d.lastSequenceNumber)
	}
	if len(nackPairs) > 0 {
		// Gather a short sample of the NACKed sequence numbers for logging.
		const sampleCap = 16
		sample := make([]uint16, 0, sampleCap)
		for i := 0; i < len(nackPairs) && i < sampleCap; i++ {
			sample = append(sample, nackPairs[i].PacketID)
		}
		log.Printf("RtpPacketLossDetector: building RTCP NACK: count=%d sample=%v senderSSRC=%d mediaSSRC=%d",
			len(nackPairs), sample, d.ssrc, d.ssrc)
		nack := &rtcp.TransportLayerNack{
			SenderSSRC: d.ssrc,
			MediaSSRC:  d.ssrc,
			Nacks:      nackPairs,
		}
		log.Printf("RtpPacketLossDetector: returning %d RTCP packet(s)", 1)
		return []rtcp.Packet{nack}
	}
	log.Printf("RtpPacketLossDetector: no NACK to send for seq=%d (pending=%d)", p.SequenceNumber, len(d.pendingNacks))
	return nil
}

const retransmissionBufferSize = 256 // Store last 256 packets

type RetransmissionBufferStore struct {
	buffers map[string]*RetransmissionBuffer
}

func NewRetransmissionBufferStore() *RetransmissionBufferStore {
	log.Printf("RetransmissionBufferStore: creating new store")
	return &RetransmissionBufferStore{
		buffers: make(map[string]*RetransmissionBuffer),
	}
}

// RetransmissionBuffer holds sent RTP packets for a short time to handle NACKs.
type RetransmissionBuffer struct {
	sync.RWMutex
	buffer          map[uint16]*rtp.Packet
	sequenceNumbers []uint16 // Used to know which packet is the oldest
}

func NewRetransmissionBuffer() *RetransmissionBuffer {
	log.Printf("RetransmissionBuffer: creating new buffer (capacity=%d)", retransmissionBufferSize)
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
		log.Printf("RetransmissionBuffer: capacity reached, evicting oldest seq=%d", oldestSeq)
		delete(b.buffer, oldestSeq)
		b.sequenceNumbers = b.sequenceNumbers[1:]
	}

	b.buffer[p.SequenceNumber] = p
	b.sequenceNumbers = append(b.sequenceNumbers, p.SequenceNumber)
	log.Printf("RetransmissionBuffer: added seq=%d size=%d", p.SequenceNumber, len(b.sequenceNumbers))
}

// Get retrieves a packet from the buffer by its sequence number.
func (b *RetransmissionBuffer) Get(seq uint16) (*rtp.Packet, bool) {
	b.RLock()
	defer b.RUnlock()
	p, ok := b.buffer[seq]
	if ok {
		log.Printf("RetransmissionBuffer: hit for seq=%d", seq)
	} else {
		log.Printf("RetransmissionBuffer: miss for seq=%d", seq)
	}
	return p, ok
}

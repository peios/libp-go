package event

import (
	"errors"
	"fmt"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"github.com/peios/libp-go/errno"
	"github.com/peios/libp-go/wire"
	uapi "github.com/peios/pkm/uapi/go"
)

// Ring-buffer layout constants and producer-metadata offsets.
const (
	metaTotal   = uapi.KMES_METADATA_TOTAL_SIZE
	metaPage    = uapi.KMES_METADATA_PAGE_SIZE
	pVersion    = uapi.KMES_PRODUCER_VERSION_OFFSET
	pCPUID      = uapi.KMES_PRODUCER_CPU_ID_OFFSET
	pGeneration = uapi.KMES_PRODUCER_GENERATION_OFFSET
	pWritePos   = uapi.KMES_PRODUCER_WRITE_POS_OFFSET
	pTailPos    = uapi.KMES_PRODUCER_TAIL_POS_OFFSET
	pFutex      = uapi.KMES_PRODUCER_FUTEX_COUNTER_OFFSET
	ringVersion = uapi.KMES_RING_VERSION
)

// futex syscall constants (Linux x86_64). The wait is deliberately
// shared — no FUTEX_PRIVATE_FLAG — because KMES wakes consumers via the
// shared futex key of the producer page's backing inode.
const (
	sysFutex    = 202
	futexWaitOp = 0
)

// Sentinel errors from the ring-consumer path.
var (
	// ErrInterrupted is returned when a blocking Read / ReadTimeout is
	// interrupted by a signal. Per PSD-003 the ring-read path treats a
	// signal as cancellation and does not retry — the caller decides
	// whether to resume.
	ErrInterrupted = errors.New("libp/event: ring wait interrupted by a signal")
	// ErrGenerationChanged is returned, once a ring is fully drained,
	// when its buffer was resized. The caller must AttachAll again.
	ErrGenerationChanged = errors.New("libp/event: ring generation changed; re-attach required")
	// ErrBadMagic is returned when a mapped fd is not a KMES ring buffer.
	ErrBadMagic = errors.New("libp/event: ring buffer magic mismatch")
)

// Ring is a consumer attached to one per-CPU KMES ring buffer. Obtain
// one Ring per CPU from AttachAll; release it with Close.
//
// A Ring is not safe for concurrent use — Next mutates the read cursor.
type Ring struct {
	fd         int
	base       []byte // the whole mmap: metadata pages + double-mapped data
	capacity   uint64
	cpuID      uint16
	generation uint64
	readPos    uint64 // monotonic byte offset of the next event to read
	pending    uint64 // event_size of the event last yielded, not yet stepped
	lastSeq    uint64
	lostEvents uint64
}

// AttachAll attaches to every per-CPU KMES ring buffer, returning one
// Ring per CPU in CPU order. The caller's effective token must hold
// SeSecurityPrivilege. Every returned Ring must be closed.
func AttachAll() ([]*Ring, error) {
	// v0.20 kmes_attach returns one fd per cpu_id; enumerate CPUs by
	// attaching cpu_id 0, 1, ... until the kernel reports EINVAL (cpu_id
	// past the CPU count). Rings mapped so far are closed on any error.
	rings := make([]*Ring, 0)
	for cpuID := uint32(0); ; cpuID++ {
		fd, capacity, err := attach(cpuID)
		if err != nil {
			if errors.Is(err, errno.EINVAL) {
				break
			}
			for _, r := range rings {
				r.Close()
			}
			return nil, fmt.Errorf("libp/event: attach cpu %d: %w", cpuID, err)
		}
		ring, err := mapRing(fd, capacity)
		if err != nil {
			for _, r := range rings {
				r.Close()
			}
			return nil, err
		}
		rings = append(rings, ring)
	}
	if len(rings) == 0 {
		return nil, fmt.Errorf("libp/event: attach: kernel reported no ring buffers")
	}
	return rings, nil
}

// attach issues one kmes_attach(cpu_id, &capacity) syscall and returns the
// per-CPU ring fd and its capacity.
func attach(cpuID uint32) (int, uint64, error) {
	var capacity uint64
	r1, err := retry(func() (uintptr, syscall.Errno) {
		r, _, e := syscall.Syscall(uapi.SYS_KMES_ATTACH,
			uintptr(cpuID),
			uintptr(unsafe.Pointer(&capacity)),
			0)
		return r, e
	})
	if err != nil {
		return -1, 0, err
	}
	return int(r1), capacity, nil
}

// mapRing mmaps one ring-buffer fd and validates its producer metadata.
func mapRing(fd int, capacity uint64) (*Ring, error) {
	mapLen := metaTotal + 2*int(capacity)
	base, err := syscall.Mmap(fd, 0, mapLen,
		syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_SHARED)
	if err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("libp/event: map ring buffer: %w", err)
	}
	if string(base[:8]) != uapi.KMES_RING_MAGIC {
		syscall.Munmap(base)
		syscall.Close(fd)
		return nil, ErrBadMagic
	}
	r := &Ring{fd: fd, base: base, capacity: capacity}
	if v := r.loadU32(pVersion); v != ringVersion {
		syscall.Munmap(base)
		syscall.Close(fd)
		return nil, fmt.Errorf("libp/event: ring buffer version %d, want %d", v, ringVersion)
	}
	r.cpuID = uint16(r.loadU32(pCPUID))
	r.generation = r.loadU64(pGeneration)
	r.readPos = r.loadU64(pTailPos) // start at the oldest surviving event
	return r, nil
}

// Close unmaps and closes the ring. It is safe to call more than once.
func (r *Ring) Close() error {
	if r.base == nil {
		return nil
	}
	mErr := syscall.Munmap(r.base)
	cErr := syscall.Close(r.fd)
	r.base = nil
	r.fd = -1
	if mErr != nil || cErr != nil {
		return fmt.Errorf("libp/event: close ring: munmap=%v close=%v", mErr, cErr)
	}
	return nil
}

// CPUID is the CPU this ring belongs to.
func (r *Ring) CPUID() uint16 { return r.cpuID }

// Capacity is the data-region size in bytes (a power of two).
func (r *Ring) Capacity() uint64 { return r.capacity }

// Generation is the buffer generation observed when the ring was attached.
func (r *Ring) Generation() uint64 { return r.generation }

// LastSequence is the sequence number of the most recent event yielded
// (0 = none yet).
func (r *Ring) LastSequence() uint64 { return r.lastSeq }

// LostEvents is a running count of events lost to overwrite or drop,
// inferred from gaps in the per-CPU sequence number.
func (r *Ring) LostEvents() uint64 { return r.lostEvents }

// loadU64 / loadU32 read a producer-metadata word with acquire ordering.
func (r *Ring) loadU64(off int) uint64 {
	return atomic.LoadUint64((*uint64)(unsafe.Pointer(&r.base[off])))
}

func (r *Ring) loadU32(off int) uint32 {
	return atomic.LoadUint32((*uint32)(unsafe.Pointer(&r.base[off])))
}

// setNeedWake / clearNeedWake arm and disarm the consumer's wake request.
// need_wake is one byte in the kernel ABI; a 4-byte aligned atomic store
// of 0/1 sets that byte (little-endian) and leaves the page's unused
// trailing bytes zero.
func (r *Ring) setNeedWake() {
	atomic.StoreUint32((*uint32)(unsafe.Pointer(&r.base[metaPage])), 1)
}

func (r *Ring) clearNeedWake() {
	atomic.StoreUint32((*uint32)(unsafe.Pointer(&r.base[metaPage])), 0)
}

// Next drains one event without blocking. ok is false (with a nil error)
// when the buffer is currently empty.
//
// The returned Event borrows the ring's mapped memory; it is valid only
// until the next call to Next on this ring. To keep it longer — in
// particular to hand it to another goroutine — copy it to an OwnedEvent.
func (r *Ring) Next() (Event, bool, error) {
	// Step over the event yielded by the previous call.
	if r.pending != 0 {
		r.readPos += r.pending
		r.pending = 0
	}

	mask := r.capacity - 1
	data := r.base[metaTotal:]
	for {
		writePos := r.loadU64(pWritePos)
		if r.readPos >= writePos {
			// Drained — only now is it safe to act on a resize.
			if r.loadU64(pGeneration) != r.generation {
				return Event{}, false, ErrGenerationChanged
			}
			return Event{}, false, nil
		}

		savedTail := r.loadU64(pTailPos)
		if r.readPos < savedTail {
			// Lapped: events at the read cursor were overwritten.
			r.readPos = savedTail
			continue
		}

		// The double mapping makes [off, off+capacity) a contiguous
		// mapped range, so a capacity-sized window always spans a whole
		// event regardless of wrap.
		off := r.readPos & mask
		ev, perr := wire.ParseEvent(data[off : off+r.capacity])

		// Torn-read check: did the tail lap us while we were parsing?
		if tailAfter := r.loadU64(pTailPos); tailAfter > savedTail && r.readPos < tailAfter {
			continue
		}
		if perr != nil {
			// Not torn yet unparseable — corrupt. Skip to the oldest
			// surviving event; if the cursor cannot advance, surface it.
			if tail := r.loadU64(pTailPos); tail > r.readPos {
				r.readPos = tail
				continue
			}
			return Event{}, false, fmt.Errorf("libp/event: ring %d: %w", r.cpuID, perr)
		}

		// Gap detection: a jump in the per-CPU sequence number counts
		// overwritten or dropped events.
		if r.lastSeq != 0 && ev.Sequence > r.lastSeq+1 {
			r.lostEvents += ev.Sequence - r.lastSeq - 1
		}
		r.lastSeq = ev.Sequence
		r.pending = uint64(ev.EventSize)
		return ev, true, nil
	}
}

// Read blocks until an event is available, then returns it copied out.
// A signal during the wait surfaces as ErrInterrupted rather than being
// retried.
func (r *Ring) Read() (OwnedEvent, error) {
	for {
		ev, ok, err := r.Next()
		if err != nil {
			return OwnedEvent{}, err
		}
		if ok {
			return ownedFrom(ev), nil
		}
		if err := r.wait(nil); err != nil {
			return OwnedEvent{}, err
		}
	}
}

// ReadTimeout blocks for up to timeout waiting for an event, returning
// it copied out, or ok=false if none arrived. It may return ok=false
// before the full timeout on a spurious wake; call again to keep
// waiting. A signal surfaces as ErrInterrupted.
func (r *Ring) ReadTimeout(timeout time.Duration) (OwnedEvent, bool, error) {
	if ev, ok, err := r.Next(); err != nil {
		return OwnedEvent{}, false, err
	} else if ok {
		return ownedFrom(ev), true, nil
	}
	if err := r.wait(&timeout); err != nil {
		return OwnedEvent{}, false, err
	}
	if ev, ok, err := r.Next(); err != nil {
		return OwnedEvent{}, false, err
	} else if ok {
		return ownedFrom(ev), true, nil
	}
	return OwnedEvent{}, false, nil
}

// wait performs the PSD-003 §5.1 notification wait: arm need_wake,
// re-check for a late write, then sleep on the futex counter.
func (r *Ring) wait(timeout *time.Duration) error {
	r.setNeedWake()
	// An event may have landed between the empty drain and the need_wake
	// store; if so, do not sleep. (Go atomics are sequentially
	// consistent, so this load cannot be reordered before the store.)
	if r.loadU64(pWritePos) != r.readPos {
		r.clearNeedWake()
		return nil
	}
	counter := r.loadU32(pFutex)
	err := r.futexWait(counter, timeout)
	r.clearNeedWake()
	return err
}

// futexWait sleeps on the ring's futex counter until it leaves expected.
func (r *Ring) futexWait(expected uint32, timeout *time.Duration) error {
	var e syscall.Errno
	if timeout != nil {
		ts := syscall.NsecToTimespec(timeout.Nanoseconds())
		_, _, e = syscall.Syscall6(sysFutex,
			uintptr(unsafe.Pointer(&r.base[pFutex])),
			futexWaitOp, uintptr(expected),
			uintptr(unsafe.Pointer(&ts)), 0, 0)
	} else {
		_, _, e = syscall.Syscall6(sysFutex,
			uintptr(unsafe.Pointer(&r.base[pFutex])),
			futexWaitOp, uintptr(expected), 0, 0, 0)
	}
	switch e {
	case 0, syscall.EAGAIN, syscall.ETIMEDOUT:
		// EAGAIN: the counter already moved. ETIMEDOUT: deadline passed.
		// Both mean "go re-drain".
		return nil
	case syscall.EINTR:
		return ErrInterrupted
	default:
		return errno.Errno(e)
	}
}

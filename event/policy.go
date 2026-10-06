package event

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/peios/libp-go/errno"
	"github.com/peios/libp-go/registry"
	uapi "github.com/peios/pkm/uapi/go"
)

// The emission policy (PGSS §6.9). Before an emitter builds an event's
// payload it asks whether the event's type is switched on. The answer
// comes from the registry tree under Machine\Generic\Events: one key per
// segment of the type, each optionally holding an "Enabled" REG_DWORD of
// 0 or 1 (any other type or number is ignored). The deepest Enabled on
// the type's path wins; with none, the tier decides. An essential type
// never consults the tree.
//
// This is a query rather than a check inside Emit because the point is
// to skip building the payload, which is built by the time Emit is
// called. EmitWith does both.
//
// It is libp-go's own implementation of the same walk and caching as
// libpeios' peios_event_policy (libp-go does not link libpeios).

// Tier is an event type's tier (PGSS §6.8): what the emission policy
// decides when nothing in the registry is set.
type Tier uint8

const (
	TierEssential Tier = iota // always on; never consults the policy
	TierStandard              // on unless the policy switches it off
	TierVerbose               // off unless the policy switches it on
	TierDebug                 // off unless the policy switches it on
)

// String names the tier as a fragment declares it.
func (t Tier) String() string {
	switch t {
	case TierEssential:
		return "essential"
	case TierStandard:
		return "standard"
	case TierVerbose:
		return "verbose"
	case TierDebug:
		return "debug"
	default:
		return fmt.Sprintf("Tier(%d)", uint8(t))
	}
}

const (
	policyRoot = `Machine\Generic\Events`
	enabledVal = "Enabled"
	// unwatchedTTL is how long a policy with nothing to watch trusts
	// what it read: PGSS §6.9's one-second bound.
	unwatchedTTL = time.Second
	// policyCacheMax bounds the cache; a full cache is cleared.
	policyCacheMax = 4096
	// policyWatchBuf is one watch read. A record that does not fit
	// fails EINVAL, which rebuilds the watch with an empty queue.
	policyWatchBuf = 64 * 1024
)

// policyAncestors are watched, nearest first, while the root is absent.
var policyAncestors = []string{`Machine\Generic`, `Machine`}

// Policy is a cached, watched view of the emission policy. Open one with
// OpenPolicy and share it: decisions are serialised by a mutex.
//
// Each decision first drains a subtree watch on Machine\Generic\Events
// (non-blocking), so a committed change applies to the next decision.
// While the root is absent the nearest existing ancestor is watched for
// its creation; with nothing watchable the cache is dropped and the
// registry re-read once a second. Without a readable registry every
// decision is by tier.
type Policy struct {
	mu          sync.Mutex
	root        *registry.Key // Events, opened Read, when it exists
	rootWatched bool
	ancestor    *registry.Key // a watched ancestor while Events is absent
	retryAt     time.Time
	buf         []byte
	cache       map[string]setting
	now         func() time.Time
	closed      bool
}

// setting is one key's (or one type's resolved) Enabled: unset, off or on.
type setting uint8

const (
	unset setting = iota
	off
	on
)

// OpenPolicy opens a view of the emission policy. It never fails for
// want of a registry: with none, it decides by tier until one appears.
func OpenPolicy() *Policy {
	p := &Policy{cache: make(map[string]setting), now: time.Now}
	p.establish()
	return p
}

// Close releases the policy's registry handles. Safe to call more than
// once; a closed Policy decides by tier.
func (p *Policy) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.teardown()
	p.closed = true
	return nil
}

// Enabled reports whether eventType at tier is switched on. An error is
// caller error only (errno.EINVAL: a malformed type or an unknown tier);
// registry trouble falls back to the tier.
func (p *Policy) Enabled(eventType string, tier Tier) (bool, error) {
	segs, ok := policySegments(eventType)
	if !ok {
		return false, fmt.Errorf("libp/event: policy: malformed event type %q: %w", eventType, errno.EINVAL)
	}
	if tier > TierDebug {
		return false, fmt.Errorf("libp/event: policy: unknown tier %d: %w", tier, errno.EINVAL)
	}
	if tier == TierEssential {
		return true, nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.refresh()
	return decide(tier, p.setting(eventType, segs)), nil
}

// EmitWith emits an event if its type is switched on, calling build for
// the payload only then. It reports whether the event was emitted.
func (p *Policy) EmitWith(eventType string, tier Tier, build func() ([]byte, error)) (bool, error) {
	ok, err := p.Enabled(eventType, tier)
	if err != nil || !ok {
		return false, err
	}
	payload, err := build()
	if err != nil {
		return false, err
	}
	if err := Emit(eventType, payload); err != nil {
		return false, err
	}
	return true, nil
}

// ---- pure resolution ------------------------------------------------------

// policySegments splits an event type into its segments, or reports it
// malformed: empty, not UTF-8, an empty segment, or a segment holding a
// byte that would not name one key (`\` and `/`, which LCS treats as
// separators, or NUL).
func policySegments(eventType string) ([]string, bool) {
	if eventType == "" || !utf8.ValidString(eventType) {
		return nil, false
	}
	segs := strings.Split(eventType, ".")
	for _, s := range segs {
		if s == "" || strings.ContainsAny(s, "\\/\x00") {
			return nil, false
		}
	}
	return segs, true
}

// interpretEnabled reads an Enabled value: a REG_DWORD of 0 or 1 is a
// setting, anything else is ignored.
func interpretEnabled(v registry.Value) setting {
	if v.Kind() != registry.TypeDWORD {
		return unset
	}
	n, _ := v.Uint32()
	switch n {
	case 0:
		return off
	case 1:
		return on
	}
	return unset
}

// policyTree is the registry as the walk sees it. A nil key is one that
// is missing or may not be read; either ends the walk.
type policyTree interface {
	root() policyKey
	child(parent policyKey, segment string) policyKey
	enabled(key policyKey) setting
	release(key policyKey)
}

type policyKey any

// resolve walks Events and one key per segment; the deepest setting wins.
// unset means nothing on the path is set, and the tier decides.
func resolve(t policyTree, segs []string) setting {
	found := unset
	key := t.root()
	for depth := 0; key != nil; depth++ {
		if s := t.enabled(key); s != unset {
			found = s
		}
		if depth == len(segs) {
			t.release(key)
			break
		}
		next := t.child(key, segs[depth])
		t.release(key)
		key = next
	}
	return found
}

// decide combines a resolved setting with the tier.
func decide(tier Tier, s setting) bool {
	switch {
	case tier == TierEssential:
		return true
	case s != unset:
		return s == on
	default:
		return tier == TierStandard
	}
}

// watchNews is what a drained batch of watch records says.
type watchNews struct {
	changed bool // a record arrived: the cache is stale
	gone    bool // the watched key itself became invisible, or the stream is unusable
}

// classifyRecords classifies the records of one read, advancing by
// total_len. A KEY_DELETED in the bare form or at path_depth 0 is the
// watched key itself; a malformed buffer counts as gone.
func classifyRecords(buf []byte) watchNews {
	var n watchNews
	for off := 0; off < len(buf); {
		rec := buf[off:]
		if len(rec) < uapi.REG_WATCH_EVENT_MIN_SIZE {
			n.gone = true
			break
		}
		total := int(binary.LittleEndian.Uint32(rec[uapi.REG_WATCH_EVENT_TOTAL_LEN_OFFSET:]))
		if total < uapi.REG_WATCH_EVENT_MIN_SIZE || total > len(rec) {
			n.gone = true
			break
		}
		rec = rec[:total]
		n.changed = true
		if binary.LittleEndian.Uint16(rec[uapi.REG_WATCH_EVENT_TYPE_OFFSET:]) == uapi.REG_WATCH_KEY_DELETED {
			at := uapi.REG_WATCH_EVENT_NAME_OFFSET +
				int(binary.LittleEndian.Uint16(rec[uapi.REG_WATCH_EVENT_NAME_LEN_OFFSET:]))
			if at+2 > len(rec) || binary.LittleEndian.Uint16(rec[at:]) == 0 {
				n.gone = true
			}
		}
		off += total
	}
	return n
}

// ---- registry I/O ---------------------------------------------------------

// liveTree walks the real registry from the open Events key by relative
// opens.
type liveTree struct{ root_ *registry.Key }

func (t liveTree) root() policyKey { return t.root_ }

func (t liveTree) child(parent policyKey, segment string) policyKey {
	k, err := parent.(*registry.Key).OpenSubkey(segment, registry.QueryValue)
	if err != nil {
		return nil
	}
	return k
}

func (t liveTree) enabled(key policyKey) setting {
	v, err := key.(*registry.Key).QueryValue(enabledVal)
	if err != nil {
		return unset
	}
	return interpretEnabled(v)
}

func (t liveTree) release(key policyKey) {
	if k := key.(*registry.Key); k != t.root_ {
		k.Close()
	}
}

// arm arms a watch and makes the fd non-blocking, so a drain never waits.
func arm(k *registry.Key, filter registry.WatchFilter, subtree bool) bool {
	return k.Watch(filter, subtree) == nil && syscall.SetNonblock(k.FD(), true) == nil
}

func (p *Policy) teardown() {
	if p.root != nil {
		p.root.Close()
	}
	if p.ancestor != nil {
		p.ancestor.Close()
	}
	p.root, p.ancestor, p.rootWatched = nil, nil, false
	clear(p.cache)
}

// establish opens and watches what exists, leaving the cache empty.
func (p *Policy) establish() {
	p.teardown()
	if p.buf == nil {
		p.buf = make([]byte, policyWatchBuf)
	}
	// Twice at most: once more if Events appeared while an ancestor
	// watch was being armed, so that creation is not missed.
	for range 2 {
		k, err := registry.Open(policyRoot, registry.Read)
		if err == nil {
			if p.ancestor != nil {
				p.ancestor.Close()
				p.ancestor = nil
			}
			p.root = k
			p.rootWatched = arm(k, registry.WatchValue|registry.WatchSubkey, true)
			break
		}
		if !errors.Is(err, errno.ENOENT) || p.ancestor != nil {
			break
		}
		for _, path := range policyAncestors {
			a, err := registry.Open(path, registry.Notify)
			if err != nil {
				continue
			}
			if arm(a, registry.WatchSubkey, false) {
				p.ancestor = a
				break
			}
			a.Close()
		}
		if p.ancestor == nil {
			break
		}
	}
	if !p.rootWatched && p.ancestor == nil {
		p.retryAt = p.now().Add(unwatchedTTL)
	}
}

// drain reads every pending watch record. ok is false when nothing is
// watched.
func (p *Policy) drain() (n watchNews, ok bool) {
	var k *registry.Key
	switch {
	case p.root != nil && p.rootWatched:
		k = p.root
	case p.ancestor != nil:
		k = p.ancestor
	default:
		return n, false
	}
	for {
		r, err := syscall.Read(k.FD(), p.buf)
		if r > 0 {
			got := classifyRecords(p.buf[:r])
			n.changed = n.changed || got.changed
			n.gone = n.gone || got.gone
			if n.gone {
				return n, true
			}
			continue
		}
		if err == syscall.EINTR {
			continue
		}
		if err != nil && err != syscall.EAGAIN {
			n.changed, n.gone = true, true
		}
		return n, true
	}
}

// refresh brings the cache up to date before a decision.
func (p *Policy) refresh() {
	n, watched := p.drain()
	switch {
	case !watched:
		if !p.closed && !p.now().Before(p.retryAt) {
			p.establish()
		}
	case n.gone || (n.changed && p.ancestor != nil):
		// An ancestor watch only says "look again".
		p.establish()
	case n.changed:
		clear(p.cache)
	}
}

func (p *Policy) setting(eventType string, segs []string) setting {
	if p.root == nil {
		return unset
	}
	if s, ok := p.cache[eventType]; ok {
		return s
	}
	s := resolve(liveTree{p.root}, segs)
	if len(p.cache) >= policyCacheMax {
		clear(p.cache)
	}
	p.cache[eventType] = s
	return s
}

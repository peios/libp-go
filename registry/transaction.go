package registry

import (
	"errors"
	"fmt"
	"syscall"

	"github.com/peios/libp-go/errno"
	"github.com/peios/libp-go/internal/sys"
	"github.com/peios/libp-go/sd"
	uapi "github.com/peios/pkm/uapi/go"
)

// Transactions group mutations on keys in a single hive into an atomic
// unit (PSD-005 §5). The closure form Transact is the primary API: it
// begins a transaction, runs the body, commits on a nil return (retrying
// the retryable EBUSY/EIO commit failures), and aborts otherwise — and on
// any early return or panic, because a dropped (closed) transaction fd
// aborts.
//
// The explicit Begin handle is available underneath for callers who need a
// long-lived transaction or manual commit control.
//
// An operation joins a transaction by carrying its fd; a key op is "on" a
// key but "in" a transaction, so transactional work goes through
// tx.At(key) → TxnKey, which composes with the same layer views and reads
// as a plain Key (reads see the transaction's own uncommitted writes —
// read-your-own-writes).

// commitRetries caps EBUSY/EIO commit retries in the closure form before
// the error is surfaced. The explicit handle gives full control for
// callers who want their own backoff.
const commitRetries = 8

// Transaction is an owned transaction handle. Aborting it — explicitly via
// Abort, or by Close — aborts the transaction (the kernel's native
// close-without-commit behaviour).
type Transaction struct {
	fd int
}

// Begin starts a transaction, returning the explicit handle. Prefer
// Transact unless you need manual control. Close (or Abort) the handle
// when done; a handle dropped without a successful Commit aborts.
func Begin() (*Transaction, error) {
	r, err := sys.Retry(beginTransaction)
	if err != nil {
		return nil, fmt.Errorf("libp/registry: begin transaction: %w", err)
	}
	return &Transaction{fd: int(r)}, nil
}

// Transact runs body inside a transaction: commit on a nil return, abort
// on a non-nil return (or on an early return / panic — a closed
// transaction aborts). Results are captured through closure variables.
//
//	err := registry.Transact(func(tx *registry.Txn) error {
//	    key, err := tx.Open(`Machine\Software\Acme`, registry.SetValue)
//	    if err != nil {
//	        return err
//	    }
//	    defer key.Close()
//	    if err := tx.At(key).Base().SetValue("Mode", registry.DWORD(1)); err != nil {
//	        return err
//	    }
//	    return tx.At(key).Layer("role-x").SetValue("Mode", registry.DWORD(2))
//	})
func Transact(body func(*Txn) error) error {
	t, err := Begin()
	if err != nil {
		return err
	}
	defer t.Close() // a non-committed close aborts; harmless after a commit.
	if err := body(&Txn{t: t}); err != nil {
		return err // t.Close (deferred) aborts.
	}
	return t.commitWithRetry()
}

// FD returns the underlying kernel transaction fd, valid until Close.
func (t *Transaction) FD() int { return t.fd }

// At binds a key to this transaction for transactional reads and writes.
func (t *Transaction) At(key *Key) *TxnKey {
	return &TxnKey{key: key, txnFD: t.fd}
}

// Create starts a create-or-open for a key enlisted in this transaction.
func (t *Transaction) Create(path string) *CreateOptions {
	return Create(path).withTxn(t.fd)
}

// Open opens an existing key. Opening is not itself a mutation and does
// not bind the transaction; pass the returned key to At to operate on it
// transactionally.
func (t *Transaction) Open(path string, access Access) (*Key, error) {
	return Open(path, access)
}

// TxnState is the state of a transaction, from Transaction.Status.
type TxnState uint32

const (
	TxnActiveUnbound TxnState = uapi.REG_TXN_ACTIVE_UNBOUND // active, not yet bound to a source
	TxnActiveBound   TxnState = uapi.REG_TXN_ACTIVE_BOUND   // active and bound to a source
	TxnCommitted     TxnState = uapi.REG_TXN_COMMITTED      // commit completed
	TxnAborted       TxnState = uapi.REG_TXN_ABORTED        // explicitly or implicitly aborted
	TxnTimedOut      TxnState = uapi.REG_TXN_TIMED_OUT      // the lifetime timer fired
	TxnSourceDown    TxnState = uapi.REG_TXN_SOURCE_DOWN    // the bound source went down before completion
)

// String names the transaction state.
func (s TxnState) String() string {
	switch s {
	case TxnActiveUnbound:
		return "ActiveUnbound"
	case TxnActiveBound:
		return "ActiveBound"
	case TxnCommitted:
		return "Committed"
	case TxnAborted:
		return "Aborted"
	case TxnTimedOut:
		return "TimedOut"
	case TxnSourceDown:
		return "SourceDown"
	default:
		return fmt.Sprintf("TxnState(%d)", uint32(s))
	}
}

// Status reads the transaction's current state.
func (t *Transaction) Status() (TxnState, error) {
	args := uapi.Reg_txn_status_args{}
	if err := fdIoctl(t.fd, uapi.REG_IOC_TXN_STATUS, ptr(&args)); err != nil {
		return 0, fmt.Errorf("libp/registry: transaction status: %w", err)
	}
	return TxnState(args.State), nil
}

// Commit commits the transaction. On EBUSY/EIO the transaction stays open
// and the call may be retried; other errors are terminal. After a
// successful commit the handle is spent (Close is then harmless).
func (t *Transaction) Commit() error {
	if err := fdIoctl(t.fd, uapi.REG_IOC_COMMIT, nil); err != nil {
		return fmt.Errorf("libp/registry: commit: %w", err)
	}
	return nil
}

// commitWithRetry commits, retrying the retryable EBUSY (write-lock
// contention) and EIO (synchronous commit failure) outcomes, which leave
// the transaction open; everything else is terminal.
func (t *Transaction) commitWithRetry() error {
	for attempt := 0; ; attempt++ {
		err := fdIoctl(t.fd, uapi.REG_IOC_COMMIT, nil)
		if err == nil {
			return nil
		}
		if (errors.Is(err, errno.EBUSY) || errors.Is(err, errno.EIO)) && attempt < commitRetries {
			continue
		}
		return fmt.Errorf("libp/registry: commit: %w", err)
	}
}

// Abort aborts the transaction explicitly (equivalent to Close). It is
// safe to call more than once.
func (t *Transaction) Abort() error { return t.Close() }

// Close releases the transaction fd. A close without a prior successful
// Commit aborts the transaction. It is safe to call more than once.
func (t *Transaction) Close() error {
	if t.fd < 0 {
		return nil
	}
	err := syscall.Close(t.fd)
	t.fd = -1
	if err != nil {
		return fmt.Errorf("libp/registry: close transaction: %w", err)
	}
	return nil
}

// Txn is the restricted transaction view handed to a Transact closure: it
// can open/create keys and bind them for transactional work, but cannot
// commit or abort — the closure runner owns that.
type Txn struct {
	t *Transaction
}

// At binds a key to the transaction. See Transaction.At.
func (x *Txn) At(key *Key) *TxnKey { return x.t.At(key) }

// Create starts a create-or-open enlisted in the transaction. See
// Transaction.Create.
func (x *Txn) Create(path string) *CreateOptions { return x.t.Create(path) }

// Open opens an existing key. See Transaction.Open.
func (x *Txn) Open(path string, access Access) (*Key, error) { return x.t.Open(path, access) }

// TxnKey is a key bound to a transaction: writes and reads on it are
// enlisted in the transaction (writes mutate atomically; reads see the
// transaction's own uncommitted writes). Obtained from Transaction.At /
// Txn.At.
type TxnKey struct {
	key   *Key
	txnFD int
}

// Base returns a transactional write view targeting the base layer.
func (tk *TxnKey) Base() *LayerWrite { return newLayerWrite(tk.key, "", tk.txnFD) }

// Layer returns a transactional write view targeting the named layer.
func (tk *TxnKey) Layer(name string) *LayerWrite { return newLayerWrite(tk.key, name, tk.txnFD) }

// QueryValue reads a value within the transaction (read-your-own-writes).
func (tk *TxnKey) QueryValue(name string) (Value, error) {
	h, err := tk.key.queryValueIn(name, tk.txnFD)
	return h.Value, err
}

// QueryValueFull reads a value with its winning layer, within the
// transaction.
func (tk *TxnKey) QueryValueFull(name string) (ValueHit, error) {
	return tk.key.queryValueIn(name, tk.txnFD)
}

// TryQueryValue reads a value within the transaction, reporting a missing
// value as found=false with a nil error.
func (tk *TxnKey) TryQueryValue(name string) (value Value, found bool, err error) {
	h, err := tk.key.queryValueIn(name, tk.txnFD)
	if errors.Is(err, errno.ENOENT) {
		return Value{}, false, nil
	}
	if err != nil {
		return Value{}, false, err
	}
	return h.Value, true, nil
}

// Values enumerates all effective values within the transaction.
func (tk *TxnKey) Values() ([]NamedValue, error) { return tk.key.valuesIn(tk.txnFD) }

// Subkeys enumerates child keys within the transaction.
func (tk *TxnKey) Subkeys() ([]Subkey, error) { return tk.key.subkeysIn(tk.txnFD) }

// SetSecurity modifies the key's security descriptor within the
// transaction.
func (tk *TxnKey) SetSecurity(info sd.Info, sdBytes []byte) error {
	return tk.key.setSecurityIn(info, sdBytes, tk.txnFD)
}

package registry_test

import (
	"errors"
	"testing"

	"github.com/peios/libp-go/errno"
	"github.com/peios/libp-go/registry"
)

// These smoke tests round-trip real LCS syscalls. They skip when not run
// on a Peios kernel (the syscalls return ENOSYS there), exactly like the
// token package's tests.

// TestOpenMachineRoot opens the machine hive root, exercising the
// reg_open_key syscall path.
func TestOpenMachineRoot(t *testing.T) {
	key, err := registry.Open("Machine", registry.Read)
	if errors.Is(err, errno.ENOSYS) {
		t.Skip("reg_open_key unavailable — not a Peios kernel")
	}
	if err != nil {
		t.Fatalf("Open(Machine): %v", err)
	}
	defer key.Close()
	if key.FD() < 0 {
		t.Fatalf("Open returned an invalid fd: %d", key.FD())
	}
}

// TestTransactionBeginStatusAbort begins a transaction, reads its state
// (the REG_IOC_TXN_STATUS ioctl), and aborts it by closing — a
// side-effect-free exercise of the transaction syscall and its status
// ioctl.
func TestTransactionBeginStatusAbort(t *testing.T) {
	tx, err := registry.Begin()
	if errors.Is(err, errno.ENOSYS) {
		t.Skip("reg_begin_transaction unavailable — not a Peios kernel")
	}
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	defer tx.Close()

	state, err := tx.Status()
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	switch state {
	case registry.TxnActiveUnbound, registry.TxnActiveBound:
		// A fresh transaction is active.
	default:
		t.Fatalf("fresh transaction state = %v, want an active state", state)
	}
	if err := tx.Abort(); err != nil {
		t.Fatalf("Abort: %v", err)
	}
}

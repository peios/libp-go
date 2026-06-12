package registry

import (
	"fmt"
	"runtime"

	uapi "github.com/peios/pkm/uapi/go"
)

// LayerWrite is a write targeting one layer on one key. Every registry
// write targets a specific layer (PSD-005 §6.3): the base layer (the
// null/default) or a named layer. Obtain one from Key.Base / Key.Layer for
// an ordinary write, or TxnKey.Base / TxnKey.Layer for a write enlisted in
// a transaction. The same view backs both — it just carries a txn_fd (or
// the no-transaction sentinel).
//
// A LayerWrite holds no resources of its own; it borrows the key.
type LayerWrite struct {
	key   *Key
	layer string // "" = base layer
	txnFD int
}

func newLayerWrite(key *Key, layer string, txnFD int) *LayerWrite {
	return &LayerWrite{key: key, layer: layer, txnFD: txnFD}
}

// SetValue writes value to name (empty name = the key's default value) in
// this layer.
func (w *LayerWrite) SetValue(name string, value Value) error {
	t, data := value.Encode()
	return w.writeValue(name, t, data, 0)
}

// SetValueIf is a conditional write: it succeeds only if the layer's
// current entry for name has sequence expectedSeq (a compare-and-swap),
// failing with EAGAIN on mismatch. It prevents lost updates from
// concurrent writers in the same layer; pair it with QueryValueFull to
// read the current sequence.
func (w *LayerWrite) SetValueIf(name string, value Value, expectedSeq uint64) error {
	t, data := value.Encode()
	return w.writeValue(name, t, data, expectedSeq)
}

// TombstoneValue writes a per-value tombstone for name in this layer: it
// masks the value for all lower-precedence layers (registry.pol
// **Del.ValueName). Removing this layer makes the masked value reappear.
func (w *LayerWrite) TombstoneValue(name string) error {
	return w.writeValue(name, typeTombstone, nil, 0)
}

func (w *LayerWrite) writeValue(name string, t Type, data []byte, expectedSeq uint64) error {
	nameB := []byte(name)
	layerB := layerBytes(w.layer)
	args := uapi.Reg_set_value_args{
		Name_len:     uint32(len(nameB)),
		Name_ptr:     uint64(uintptr(bytesPtr(nameB))),
		Type:         uint32(t),
		Data_len:     uint32(len(data)),
		Data_ptr:     uint64(uintptr(bytesPtr(data))),
		Layer_len:    uint32(len(layerB)),
		Layer_ptr:    uint64(uintptr(bytesPtr(layerB))),
		Txn_fd:       int32(w.txnFD),
		Expected_seq: expectedSeq,
	}
	err := w.key.ioctl(uapi.REG_IOC_SET_VALUE, ptr(&args))
	runtime.KeepAlive(nameB)
	runtime.KeepAlive(data)
	runtime.KeepAlive(layerB)
	if err != nil {
		return fmt.Errorf("libp/registry: set value %q: %w", name, err)
	}
	return nil
}

// DeleteValue removes this layer's entry for name (whether value or
// tombstone). It is idempotent; lower-precedence layers' entries then
// become effective.
func (w *LayerWrite) DeleteValue(name string) error {
	nameB := []byte(name)
	layerB := layerBytes(w.layer)
	args := uapi.Reg_delete_value_args{
		Name_len:  uint32(len(nameB)),
		Name_ptr:  uint64(uintptr(bytesPtr(nameB))),
		Layer_len: uint32(len(layerB)),
		Layer_ptr: uint64(uintptr(bytesPtr(layerB))),
		Txn_fd:    int32(w.txnFD),
	}
	err := w.key.ioctl(uapi.REG_IOC_DELETE_VALUE, ptr(&args))
	runtime.KeepAlive(nameB)
	runtime.KeepAlive(layerB)
	if err != nil {
		return fmt.Errorf("libp/registry: delete value %q: %w", name, err)
	}
	return nil
}

// BlanketTombstone sets (true) or clears (false) this layer's blanket
// tombstone on the key: it masks all values from lower-precedence layers
// (registry.pol **DelVals).
func (w *LayerWrite) BlanketTombstone(set bool) error {
	layerB := layerBytes(w.layer)
	args := uapi.Reg_blanket_tombstone_args{
		Layer_len: uint32(len(layerB)),
		Layer_ptr: uint64(uintptr(bytesPtr(layerB))),
		Set:       boolU8(set),
		Txn_fd:    int32(w.txnFD),
	}
	err := w.key.ioctl(uapi.REG_IOC_BLANKET_TOMBSTONE, ptr(&args))
	runtime.KeepAlive(layerB)
	if err != nil {
		return fmt.Errorf("libp/registry: blanket tombstone: %w", err)
	}
	return nil
}

// DeleteKey removes the key's path entry from this layer (requires
// Delete). It does not delete child keys (ENOTEMPTY if any are visible).
func (w *LayerWrite) DeleteKey() error {
	layerB := layerBytes(w.layer)
	args := uapi.Reg_delete_key_args{
		Layer_len: uint32(len(layerB)),
		Layer_ptr: uint64(uintptr(bytesPtr(layerB))),
		Txn_fd:    int32(w.txnFD),
	}
	err := w.key.ioctl(uapi.REG_IOC_DELETE_KEY, ptr(&args))
	runtime.KeepAlive(layerB)
	if err != nil {
		return fmt.Errorf("libp/registry: delete key: %w", err)
	}
	return nil
}

// HideKey creates a HIDDEN path entry for the key in this layer, masking
// it from visibility (requires Delete). Removing the layer makes it
// reappear.
func (w *LayerWrite) HideKey() error {
	layerB := layerBytes(w.layer)
	args := uapi.Reg_hide_key_args{
		Layer_len: uint32(len(layerB)),
		Layer_ptr: uint64(uintptr(bytesPtr(layerB))),
		Txn_fd:    int32(w.txnFD),
	}
	err := w.key.ioctl(uapi.REG_IOC_HIDE_KEY, ptr(&args))
	runtime.KeepAlive(layerB)
	if err != nil {
		return fmt.Errorf("libp/registry: hide key: %w", err)
	}
	return nil
}

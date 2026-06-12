package registry

import (
	"encoding/binary"
	"errors"
	"fmt"
	"runtime"

	"github.com/peios/libp-go/errno"
	"github.com/peios/libp-go/sd"
	uapi "github.com/peios/pkm/uapi/go"
)

// Reads always return the *effective* value resolved across the whole
// layer stack, reporting which layer won (PSD-005 §6.3). They live on Key.
// Writes do not — they flow through a layer view (see write.go).
//
// Variable-length reads (query / enum / info / security) use the kernel's
// two-pass buffer ABI (§6.3): try a reasonable buffer, and on ERANGE
// regrow to the size the kernel reports and retry, bounded by
// maxProbeRetries (which absorbs a value that grows between the size probe
// and the fetch).

// Subkey is one enumerated child key — its name plus cheap metadata. From
// Key.Subkeys.
type Subkey struct {
	Name          string // the child key's name (one path component)
	LastWriteTime uint64 // source-defined last-write timestamp
	SubkeyCount   uint32 // number of child keys beneath this child
	ValueCount    uint32 // number of values on this child
}

// NamedValue is one enumerated value — its name plus decoded value. From
// Key.Values. Name is empty for the key's default value.
type NamedValue struct {
	Name  string
	Value Value
}

// ValueHit is an effective value read together with the layer that won
// resolution. From Key.QueryValueFull.
type ValueHit struct {
	Value    Value
	Layer    string // name of the winning layer ("base" for the base layer)
	Sequence uint64 // the effective entry's sequence number
}

// KeyInfo is metadata about a key. From Key.Info.
type KeyInfo struct {
	Name             string // the key's own name (last path component)
	LastWriteTime    uint64 // source-defined last-write timestamp
	SubkeyCount      uint32 // number of child keys
	ValueCount       uint32 // number of values
	MaxSubkeyNameLen uint32 // longest child-key name, in bytes
	MaxValueNameLen  uint32 // longest value name, in bytes
	MaxValueDataSize uint32 // largest value data payload, in bytes
	SDSize           uint32 // size of the key's security descriptor, in bytes
	Volatile         bool   // does not survive reboot
	Symlink          bool   // a symlink key
	HiveGeneration   uint64 // the per-hive change epoch (§6.3)
}

// QueryValue reads the effective value of name (empty name = default
// value). It fails with ENOENT if no effective value exists.
func (k *Key) QueryValue(name string) (Value, error) {
	h, err := k.queryValueIn(name, noTxn)
	return h.Value, err
}

// QueryValueFull is like QueryValue but also reports the winning layer and
// sequence number.
func (k *Key) QueryValueFull(name string) (ValueHit, error) {
	return k.queryValueIn(name, noTxn)
}

// TryQueryValue is like QueryValue but reports a missing value as
// found=false with a nil error rather than an ENOENT error.
func (k *Key) TryQueryValue(name string) (value Value, found bool, err error) {
	h, err := k.queryValueIn(name, noTxn)
	if errors.Is(err, errno.ENOENT) {
		return Value{}, false, nil
	}
	if err != nil {
		return Value{}, false, err
	}
	return h.Value, true, nil
}

// Values reads every effective value on this key in one consistent
// snapshot (QUERY_VALUES_BATCH).
func (k *Key) Values() ([]NamedValue, error) {
	return k.valuesIn(noTxn)
}

// Subkeys reads every visible child key of this key.
func (k *Key) Subkeys() ([]Subkey, error) {
	return k.subkeysIn(noTxn)
}

// Info reads this key's metadata.
func (k *Key) Info() (KeyInfo, error) {
	name := make([]byte, nameCapHint)
	for range maxProbeRetries {
		args := uapi.Reg_query_key_info_args{
			Name_ptr: uint64(uintptr(bytesPtr(name))),
			Name_len: uint32(len(name)),
		}
		err := k.ioctl(uapi.REG_IOC_QUERY_KEY_INFO, ptr(&args))
		runtime.KeepAlive(name)
		if errors.Is(err, errno.ERANGE) {
			name = make([]byte, args.Name_len)
			continue
		}
		if err != nil {
			return KeyInfo{}, fmt.Errorf("libp/registry: key info: %w", err)
		}
		return KeyInfo{
			Name:             string(name[:args.Name_len]),
			LastWriteTime:    args.Last_write_time,
			SubkeyCount:      args.Subkey_count,
			ValueCount:       args.Value_count,
			MaxSubkeyNameLen: args.Max_subkey_name_len,
			MaxValueNameLen:  args.Max_value_name_len,
			MaxValueDataSize: args.Max_value_data_size,
			SDSize:           args.Sd_size,
			Volatile:         args.Volatile_key != 0,
			Symlink:          args.Symlink != 0,
			HiveGeneration:   args.Hive_generation,
		}, nil
	}
	return KeyInfo{}, fmt.Errorf("libp/registry: key info: %w", errno.ERANGE)
}

// Security reads the key's security descriptor, returning the raw
// self-relative bytes — decode them with sd.ParseDescriptor. info selects
// which components to return (owner / group / DACL / SACL).
func (k *Key) Security(info sd.Info) ([]byte, error) {
	buf := make([]byte, sdCapHint)
	for range maxProbeRetries {
		args := uapi.Reg_get_security_args{
			Security_info: uint32(info),
			Sd_ptr:        uint64(uintptr(bytesPtr(buf))),
			Sd_len:        uint32(len(buf)),
		}
		err := k.ioctl(uapi.REG_IOC_GET_SECURITY, ptr(&args))
		runtime.KeepAlive(buf)
		if errors.Is(err, errno.ERANGE) {
			buf = make([]byte, args.Sd_len)
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("libp/registry: get security: %w", err)
		}
		return buf[:args.Sd_len], nil
	}
	return nil, fmt.Errorf("libp/registry: get security: %w", errno.ERANGE)
}

// SetSecurity writes sdBytes — a self-relative security descriptor — to the
// key. info selects which components are applied. SD changes are not
// layer-qualified — they mutate the key directly.
func (k *Key) SetSecurity(info sd.Info, sdBytes []byte) error {
	return k.setSecurityIn(info, sdBytes, noTxn)
}

// Flush forces the source to persist this hive's pending writes (requires
// SetValue).
func (k *Key) Flush() error {
	if err := k.ioctl(uapi.REG_IOC_FLUSH, nil); err != nil {
		return fmt.Errorf("libp/registry: flush: %w", err)
	}
	return nil
}

// Backup exports this key and its entire subtree to outputFD in the
// standard backup format (requires SeBackupPrivilege).
func (k *Key) Backup(outputFD int) error {
	args := uapi.Reg_backup_args{Output_fd: int32(outputFD)}
	if err := k.ioctl(uapi.REG_IOC_BACKUP, ptr(&args)); err != nil {
		return fmt.Errorf("libp/registry: backup: %w", err)
	}
	return nil
}

// Restore replaces this key and its entire subtree from inputFD (requires
// SeRestorePrivilege; atomic — rolled back on any failure).
func (k *Key) Restore(inputFD int) error {
	args := uapi.Reg_restore_args{Input_fd: int32(inputFD)}
	if err := k.ioctl(uapi.REG_IOC_RESTORE, ptr(&args)); err != nil {
		return fmt.Errorf("libp/registry: restore: %w", err)
	}
	return nil
}

// --- Internal probe impls (shared with TxnKey for read-your-own-writes) --

func (k *Key) queryValueIn(name string, txnFD int) (ValueHit, error) {
	nameB := []byte(name)
	data := make([]byte, dataCapHint)
	layer := make([]byte, nameCapHint)
	for range maxProbeRetries {
		args := uapi.Reg_query_value_args{
			Name_len:      uint32(len(nameB)),
			Name_ptr:      uint64(uintptr(bytesPtr(nameB))),
			Txn_fd:        int32(txnFD),
			Data_len:      uint32(len(data)),
			Data_ptr:      uint64(uintptr(bytesPtr(data))),
			Layer_buf_len: uint32(len(layer)),
			Layer_ptr:     uint64(uintptr(bytesPtr(layer))),
		}
		err := k.ioctl(uapi.REG_IOC_QUERY_VALUE, ptr(&args))
		runtime.KeepAlive(nameB)
		runtime.KeepAlive(data)
		runtime.KeepAlive(layer)
		if errors.Is(err, errno.ERANGE) {
			data = make([]byte, args.Data_len)
			layer = make([]byte, args.Layer_len)
			continue
		}
		if err != nil {
			return ValueHit{}, fmt.Errorf("libp/registry: query value %q: %w", name, err)
		}
		v, derr := Decode(Type(args.Type), data[:args.Data_len])
		if derr != nil {
			return ValueHit{}, derr
		}
		return ValueHit{
			Value:    v,
			Layer:    string(layer[:args.Layer_len]),
			Sequence: args.Sequence,
		}, nil
	}
	return ValueHit{}, fmt.Errorf("libp/registry: query value %q: %w", name, errno.ERANGE)
}

func (k *Key) valuesIn(txnFD int) ([]NamedValue, error) {
	buf := make([]byte, dataCapHint*4)
	for range maxProbeRetries {
		args := uapi.Reg_query_values_batch_args{
			Buf_len: uint32(len(buf)),
			Buf_ptr: uint64(uintptr(bytesPtr(buf))),
			Txn_fd:  int32(txnFD),
		}
		err := k.ioctl(uapi.REG_IOC_QUERY_VALUES_BATCH, ptr(&args))
		runtime.KeepAlive(buf)
		if errors.Is(err, errno.ERANGE) {
			buf = make([]byte, args.Buf_len)
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("libp/registry: query values: %w", err)
		}
		return parseBatch(buf[:args.Buf_len], int(args.Count))
	}
	return nil, fmt.Errorf("libp/registry: query values: %w", errno.ERANGE)
}

func (k *Key) subkeysIn(txnFD int) ([]Subkey, error) {
	var out []Subkey
	for index := uint32(0); ; index++ {
		sk, ok, err := k.enumSubkeyAt(index, txnFD)
		if err != nil {
			return nil, err
		}
		if !ok {
			return out, nil
		}
		out = append(out, sk)
	}
}

func (k *Key) enumSubkeyAt(index uint32, txnFD int) (Subkey, bool, error) {
	name := make([]byte, nameCapHint)
	for range maxProbeRetries {
		args := uapi.Reg_enum_subkey_args{
			Index:    index,
			Name_len: uint32(len(name)),
			Name_ptr: uint64(uintptr(bytesPtr(name))),
			Txn_fd:   int32(txnFD),
		}
		err := k.ioctl(uapi.REG_IOC_ENUM_SUBKEYS, ptr(&args))
		runtime.KeepAlive(name)
		if errors.Is(err, errno.ENOENT) {
			return Subkey{}, false, nil // past the last subkey
		}
		if errors.Is(err, errno.ERANGE) {
			name = make([]byte, args.Name_len)
			continue
		}
		if err != nil {
			return Subkey{}, false, fmt.Errorf("libp/registry: enum subkey %d: %w", index, err)
		}
		return Subkey{
			Name:          string(name[:args.Name_len]),
			LastWriteTime: args.Last_write_time,
			SubkeyCount:   args.Subkey_count,
			ValueCount:    args.Value_count,
		}, true, nil
	}
	return Subkey{}, false, fmt.Errorf("libp/registry: enum subkey %d: %w", index, errno.ERANGE)
}

func (k *Key) setSecurityIn(info sd.Info, sdBytes []byte, txnFD int) error {
	args := uapi.Reg_set_security_args{
		Security_info: uint32(info),
		Sd_len:        uint32(len(sdBytes)),
		Sd_ptr:        uint64(uintptr(bytesPtr(sdBytes))),
		Txn_fd:        int32(txnFD),
	}
	err := k.ioctl(uapi.REG_IOC_SET_SECURITY, ptr(&args))
	runtime.KeepAlive(sdBytes)
	if err != nil {
		return fmt.Errorf("libp/registry: set security: %w", err)
	}
	return nil
}

// parseBatch parses the packed buffer from REG_IOC_QUERY_VALUES_BATCH:
// count entries of [name_len u32][name][type u32][data_len u32][data], no
// padding.
func parseBatch(buf []byte, count int) ([]NamedValue, error) {
	out := make([]NamedValue, 0, count)
	off := 0
	for range count {
		if off+4 > len(buf) {
			break
		}
		nameLen := int(binary.LittleEndian.Uint32(buf[off:]))
		off += 4
		if off+nameLen > len(buf) {
			break
		}
		name := string(buf[off : off+nameLen])
		off += nameLen
		if off+8 > len(buf) {
			break
		}
		t := Type(binary.LittleEndian.Uint32(buf[off:]))
		dataLen := int(binary.LittleEndian.Uint32(buf[off+4:]))
		off += 8
		if off+dataLen > len(buf) {
			break
		}
		v, err := Decode(t, buf[off:off+dataLen])
		if err != nil {
			return nil, err
		}
		out = append(out, NamedValue{Name: name, Value: v})
		off += dataLen
	}
	return out, nil
}

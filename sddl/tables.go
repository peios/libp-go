package sddl

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/peios/libp-go/sd"
	"github.com/peios/libp-go/wire"
	uapi "github.com/peios/pkm/uapi/go"
)

// --- SID aliases -----------------------------------------------------

// aliasKind tells how an SDDL SID alias resolves to a SID.
type aliasKind uint8

const (
	aliasAbsolute aliasKind = iota // a fixed, context-free SID
	aliasDomain                    // the domain SID with a RID appended
	aliasMachine                   // the machine SID with a RID appended
)

// aliasEntry is one row of the SDDL SID-alias table.
type aliasEntry struct {
	kind aliasKind
	sid  wire.SID // aliasAbsolute: the resolved SID
	rid  uint32   // aliasDomain / aliasMachine: the RID to append
}

// mustSID builds a SID that is known at authoring time to be valid.
func mustSID(authority uint64, subs ...uint32) wire.SID {
	s, err := wire.NewSID(authority, subs...)
	if err != nil {
		panic("sddl: malformed built-in SID: " + err.Error())
	}
	return s
}

// sidAliases is the MS-DTYP two-letter SID alias table. Absolute
// aliases resolve context-free; domain- and machine-relative aliases
// need sddl.WithDomain / sddl.WithMachine. Entries that name an
// sd.WellKnown principal delegate to it, so the SID has one definition.
var sidAliases = map[string]aliasEntry{
	// World, logon-type and creator principals.
	"WD": {sid: sd.Everyone.SID()},
	"AN": {sid: sd.Anonymous.SID()},
	"AU": {sid: sd.AuthenticatedUsers.SID()},
	"IU": {sid: mustSID(5, 4)},  // Interactive
	"NU": {sid: mustSID(5, 2)},  // Network logon
	"SU": {sid: mustSID(5, 6)},  // Service logon
	"RC": {sid: mustSID(5, 12)}, // Restricted code
	"WR": {sid: mustSID(5, 33)}, // Write-restricted code
	"PS": {sid: mustSID(5, 10)}, // Principal self
	"CO": {sid: sd.CreatorOwner.SID()},
	"CG": {sid: sd.CreatorGroup.SID()},
	"OW": {sid: mustSID(3, 4)},     // Owner rights
	"ED": {sid: mustSID(5, 9)},     // Enterprise domain controllers
	"AC": {sid: mustSID(15, 2, 1)}, // All application packages
	"SY": {sid: sd.LocalSystem.SID()},
	"LS": {sid: sd.LocalService.SID()},
	"NS": {sid: sd.NetworkService.SID()},

	// Integrity levels.
	"LW": {sid: sd.LowIL.SID()},
	"ME": {sid: sd.MediumIL.SID()},
	"MP": {sid: sd.MediumPlusIL.SID()},
	"HI": {sid: sd.HighIL.SID()},
	"SI": {sid: sd.SystemIL.SID()},

	// The BUILTIN domain (S-1-5-32-*) — absolute.
	"BA": {sid: sd.BuiltinAdministrators.SID()},
	"BU": {sid: sd.BuiltinUsers.SID()},
	"BG": {sid: mustSID(5, 32, 546)},
	"PU": {sid: mustSID(5, 32, 547)},
	"AO": {sid: mustSID(5, 32, 548)},
	"SO": {sid: mustSID(5, 32, 549)},
	"PO": {sid: mustSID(5, 32, 550)},
	"BO": {sid: mustSID(5, 32, 551)},
	"RE": {sid: mustSID(5, 32, 552)},
	"RU": {sid: mustSID(5, 32, 554)},
	"RD": {sid: mustSID(5, 32, 555)},
	"NO": {sid: mustSID(5, 32, 556)},
	"MU": {sid: mustSID(5, 32, 558)},
	"LU": {sid: mustSID(5, 32, 559)},
	"IS": {sid: mustSID(5, 32, 568)},
	"CY": {sid: mustSID(5, 32, 569)},
	"ER": {sid: mustSID(5, 32, 573)},
	"CD": {sid: mustSID(5, 32, 574)},
	"RA": {sid: mustSID(5, 32, 575)},
	"ES": {sid: mustSID(5, 32, 576)},
	"MS": {sid: mustSID(5, 32, 577)},
	"HA": {sid: mustSID(5, 32, 578)},
	"AA": {sid: mustSID(5, 32, 579)},
	"RM": {sid: mustSID(5, 32, 580)},

	// Domain-relative — need sddl.WithDomain.
	"RO": {kind: aliasDomain, rid: 498},
	"DA": {kind: aliasDomain, rid: 512},
	"DU": {kind: aliasDomain, rid: 513},
	"DG": {kind: aliasDomain, rid: 514},
	"DC": {kind: aliasDomain, rid: 515},
	"DD": {kind: aliasDomain, rid: 516},
	"CA": {kind: aliasDomain, rid: 517},
	"SA": {kind: aliasDomain, rid: 518},
	"EA": {kind: aliasDomain, rid: 519},
	"PA": {kind: aliasDomain, rid: 520},
	"CN": {kind: aliasDomain, rid: 522},
	"AP": {kind: aliasDomain, rid: 525},
	"KA": {kind: aliasDomain, rid: 526},
	"EK": {kind: aliasDomain, rid: 527},
	"RS": {kind: aliasDomain, rid: 553},

	// Machine-relative — need sddl.WithMachine.
	"LA": {kind: aliasMachine, rid: 500},
	"LG": {kind: aliasMachine, rid: 501},
}

// absAliasBySID is the reverse of the absolute aliases, for Format.
var absAliasBySID = map[wire.SID]string{}

// resolveAlias maps a two-letter SDDL alias to its SID. A domain- or
// machine-relative alias needs the matching resolution context.
func (o options) resolveAlias(name string) (wire.SID, error) {
	e, ok := sidAliases[name]
	if !ok {
		return wire.SID{}, fmt.Errorf("unknown SID alias %q", name)
	}
	switch e.kind {
	case aliasDomain:
		if !o.domain.IsValid() {
			return wire.SID{}, fmt.Errorf("domain-relative alias %q needs a domain context (sddl.WithDomain)", name)
		}
		return o.domain.Child(e.rid)
	case aliasMachine:
		if !o.machine.IsValid() {
			return wire.SID{}, fmt.Errorf("machine-relative alias %q needs a machine context (sddl.WithMachine)", name)
		}
		return o.machine.Child(e.rid)
	default:
		return e.sid, nil
	}
}

// parseSIDText resolves an SDDL SID token — an "S-1-…" literal or a
// two-letter alias — to a SID.
func (o options) parseSIDText(text string) (wire.SID, error) {
	if strings.HasPrefix(text, "S-") {
		return wire.SIDFromString(text)
	}
	return o.resolveAlias(text)
}

// formatSID renders a SID as its alias where one is known, else as the
// raw S-1-… form. Domain- and machine-relative aliases are recognised
// only when the matching context is supplied.
func (o options) formatSID(s wire.SID) string {
	if name, ok := absAliasBySID[s]; ok {
		return name
	}
	if o.domain.IsValid() {
		if name, ok := relativeAlias(o.domain, s, aliasDomain); ok {
			return name
		}
	}
	if o.machine.IsValid() {
		if name, ok := relativeAlias(o.machine, s, aliasMachine); ok {
			return name
		}
	}
	return s.String()
}

// relativeAlias finds a domain- or machine-relative alias whose RID,
// appended to base, yields s.
func relativeAlias(base, s wire.SID, kind aliasKind) (string, bool) {
	for name, e := range sidAliases {
		if e.kind != kind {
			continue
		}
		if c, err := base.Child(e.rid); err == nil && c == s {
			return name, true
		}
	}
	return "", false
}

// --- access-mask rights ----------------------------------------------

// File generic-access masks, composed from the KACS file and standard
// rights bits (KACS uses the MS-DTYP ACE bit layout).
const (
	fileRead = uapi.KACS_ACCESS_READ_CONTROL | uapi.KACS_ACCESS_SYNCHRONIZE |
		uapi.KACS_FILE_READ_DATA | uapi.KACS_FILE_READ_EA | uapi.KACS_FILE_READ_ATTRIBUTES
	fileWrite = uapi.KACS_ACCESS_READ_CONTROL | uapi.KACS_ACCESS_SYNCHRONIZE |
		uapi.KACS_FILE_WRITE_DATA | uapi.KACS_FILE_APPEND_DATA |
		uapi.KACS_FILE_WRITE_EA | uapi.KACS_FILE_WRITE_ATTRIBUTES
	fileExecute = uapi.KACS_ACCESS_READ_CONTROL | uapi.KACS_ACCESS_SYNCHRONIZE |
		uapi.KACS_FILE_EXECUTE | uapi.KACS_FILE_READ_ATTRIBUTES
	fileAll = uapi.KACS_ACCESS_DELETE | uapi.KACS_ACCESS_READ_CONTROL |
		uapi.KACS_ACCESS_WRITE_DAC | uapi.KACS_ACCESS_WRITE_OWNER |
		uapi.KACS_ACCESS_SYNCHRONIZE |
		uapi.KACS_FILE_READ_DATA | uapi.KACS_FILE_WRITE_DATA | uapi.KACS_FILE_APPEND_DATA |
		uapi.KACS_FILE_READ_EA | uapi.KACS_FILE_WRITE_EA | uapi.KACS_FILE_EXECUTE |
		uapi.KACS_FILE_DELETE_CHILD | uapi.KACS_FILE_READ_ATTRIBUTES | uapi.KACS_FILE_WRITE_ATTRIBUTES
)

// rightsMnemonics maps SDDL two-letter rights codes to access-mask
// bits. Generic and standard codes come from the KACS access-mask
// constants; the file codes are composed above; the directory-service
// object rights and the mandatory-label policy bits are MS-DTYP
// wire-format values, which KACS follows.
//
// TODO(sddl): add the registry rights mnemonics KA/KR/KW/KX once LCS
// publishes its registry-rights model. They are intentionally absent
// for now — LCS, not KACS, owns registry rights; an LCS object's
// rights go in as a hex mask meanwhile.
var rightsMnemonics = map[string]uint32{
	"GA": uapi.KACS_ACCESS_GENERIC_ALL,
	"GR": uapi.KACS_ACCESS_GENERIC_READ,
	"GW": uapi.KACS_ACCESS_GENERIC_WRITE,
	"GX": uapi.KACS_ACCESS_GENERIC_EXECUTE,
	"RC": uapi.KACS_ACCESS_READ_CONTROL,
	"SD": uapi.KACS_ACCESS_DELETE,
	"WD": uapi.KACS_ACCESS_WRITE_DAC,
	"WO": uapi.KACS_ACCESS_WRITE_OWNER,
	"FA": fileAll,
	"FR": fileRead,
	"FW": fileWrite,
	"FX": fileExecute,
	// Directory-service object rights (MS-DTYP §2.4.4.3).
	"CC": 0x001, "DC": 0x002, "LC": 0x004, "SW": 0x008,
	"RP": 0x010, "WP": 0x020, "DT": 0x040, "LO": 0x080, "CR": 0x100,
	// Mandatory-label policy bits (MS-DTYP §2.4.4.13).
	"NW": 0x001, "NR": 0x002, "NX": 0x004,
}

// parseMask decodes an SDDL rights field — "0x"-prefixed hex, decimal,
// or a run of two-letter mnemonics; the empty field is mask zero.
func parseMask(field string) (uint32, error) {
	if field == "" {
		return 0, nil
	}
	if len(field) > 2 && (field[:2] == "0x" || field[:2] == "0X") {
		v, err := strconv.ParseUint(field[2:], 16, 32)
		if err != nil {
			return 0, fmt.Errorf("malformed hex access mask %q", field)
		}
		return uint32(v), nil
	}
	if isAllDigits(field) {
		v, err := strconv.ParseUint(field, 10, 32)
		if err != nil {
			return 0, fmt.Errorf("malformed access mask %q", field)
		}
		return uint32(v), nil
	}
	if len(field)%2 != 0 {
		return 0, fmt.Errorf("malformed rights mnemonics %q", field)
	}
	var mask uint32
	for i := 0; i < len(field); i += 2 {
		code := field[i : i+2]
		bit, ok := rightsMnemonics[code]
		if !ok {
			return 0, fmt.Errorf("unknown rights mnemonic %q", code)
		}
		mask |= bit
	}
	return mask, nil
}

// formatMask renders an access mask as hex. SDDL rights mnemonics are
// object-class-dependent and lossy; hex is canonical and exact.
func formatMask(m uint32) string {
	if m == 0 {
		return ""
	}
	return fmt.Sprintf("0x%x", m)
}

func isAllDigits(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return len(s) > 0
}

// --- ACE types -------------------------------------------------------

// aceTypeTags maps SDDL ACE-type tags to ACE types. The callback,
// resource-attribute and exotic system types are listed so a parse
// error can name them precisely; aceTypeSupported reports which ones
// the structured codec can yet handle.
var aceTypeTags = map[string]sd.AceType{
	"A":  sd.AceAccessAllowed,
	"D":  sd.AceAccessDenied,
	"OA": sd.AceAccessAllowedObject,
	"OD": sd.AceAccessDeniedObject,
	"AU": sd.AceSystemAudit,
	"AL": sd.AceSystemAlarm,
	"OU": sd.AceSystemAuditObject,
	"OL": sd.AceSystemAlarmObject,
	"ML": sd.AceSystemMandatoryLabel,
	"XA": sd.AceAccessAllowedCallback,
	"XD": sd.AceAccessDeniedCallback,
	"XU": sd.AceSystemAuditCallback,
	"ZA": sd.AceAccessAllowedCallbackObject,
	"RA": sd.AceSystemResourceAttribute,
	"SP": sd.AceSystemScopedPolicyID,
	"TL": sd.AceSystemProcessTrustLabel,
	"FL": sd.AceSystemAccessFilter,
}

var aceTagByType = map[sd.AceType]string{}

// aceTypeSupported reports whether the SDDL codec can encode or decode
// an ACE of this type — the structured types and the callback
// (conditional) types. Resource-attribute and the exotic system types
// remain unsupported.
func aceTypeSupported(t sd.AceType) bool {
	switch t {
	case sd.AceAccessAllowed, sd.AceAccessDenied,
		sd.AceSystemAudit, sd.AceSystemAlarm, sd.AceSystemMandatoryLabel,
		sd.AceAccessAllowedObject, sd.AceAccessDeniedObject,
		sd.AceSystemAuditObject, sd.AceSystemAlarmObject,
		sd.AceAccessAllowedCallback, sd.AceAccessDeniedCallback,
		sd.AceSystemAuditCallback, sd.AceAccessAllowedCallbackObject:
		return true
	default:
		return false
	}
}

// isCallbackType reports whether an ACE type carries a trailing
// conditional expression — the SDDL XA / XD / XU / ZA types.
func isCallbackType(t sd.AceType) bool {
	switch t {
	case sd.AceAccessAllowedCallback, sd.AceAccessDeniedCallback,
		sd.AceSystemAuditCallback, sd.AceAccessAllowedCallbackObject:
		return true
	default:
		return false
	}
}

// isObjectType reports whether an ACE type carries object-type GUIDs.
func isObjectType(t sd.AceType) bool {
	switch t {
	case sd.AceAccessAllowedObject, sd.AceAccessDeniedObject,
		sd.AceSystemAuditObject, sd.AceSystemAlarmObject:
		return true
	default:
		return false
	}
}

// --- ACE flags -------------------------------------------------------

// aceFlagText pairs each ACE inheritance/audit flag with its SDDL code,
// in canonical output order.
var aceFlagText = []struct {
	bit  sd.AceFlags
	code string
}{
	{sd.FlagContainerInherit, "CI"},
	{sd.FlagObjectInherit, "OI"},
	{sd.FlagNoPropagateInherit, "NP"},
	{sd.FlagInheritOnly, "IO"},
	{sd.FlagInherited, "ID"},
	{sd.FlagSuccessfulAccess, "SA"},
	{sd.FlagFailedAccess, "FA"},
}

var (
	aceFlagByCode = map[string]sd.AceFlags{}
	knownAceFlags sd.AceFlags
)

// textToAceFlags decodes a run of two-letter ACE-flag codes.
func textToAceFlags(s string) (sd.AceFlags, error) {
	if len(s)%2 != 0 {
		return 0, fmt.Errorf("malformed ACE flags %q", s)
	}
	var f sd.AceFlags
	for i := 0; i < len(s); i += 2 {
		code := s[i : i+2]
		bit, ok := aceFlagByCode[code]
		if !ok {
			return 0, fmt.Errorf("unknown ACE flag %q", code)
		}
		f |= bit
	}
	return f, nil
}

// aceFlagsToText renders ACE flags as their concatenated SDDL codes.
func aceFlagsToText(f sd.AceFlags) string {
	var b strings.Builder
	for _, e := range aceFlagText {
		if f&e.bit != 0 {
			b.WriteString(e.code)
		}
	}
	return b.String()
}

// --- ACL control bits ------------------------------------------------

// controlDACLAutoInheritReq / controlSACLAutoInheritReq are the MS-DTYP
// control bits behind the SDDL "AR" flag (SE_DACL_AUTO_INHERIT_REQ /
// SE_SACL_AUTO_INHERIT_REQ). KACS exposes no named constant for them;
// the raw bit values are used so an "AR" flag survives a round trip.
const (
	controlDACLAutoInheritReq sd.Control = 0x0100
	controlSACLAutoInheritReq sd.Control = 0x0200
)

func init() {
	for name, e := range sidAliases {
		if e.kind != aliasAbsolute {
			continue
		}
		if prev, ok := absAliasBySID[e.sid]; !ok || name < prev {
			absAliasBySID[e.sid] = name
		}
	}
	for tag, t := range aceTypeTags {
		if prev, ok := aceTagByType[t]; !ok || tag < prev {
			aceTagByType[t] = tag
		}
	}
	for _, e := range aceFlagText {
		aceFlagByCode[e.code] = e.bit
		knownAceFlags |= e.bit
	}
}

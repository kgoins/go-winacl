package winacl

import (
	"fmt"
	"strings"

	"github.com/audibleblink/bamflags"
)

var AceHeaderTypeSDDL = map[AceType]string{
	AceTypeAccessAllowed:               "A",
	AceTypeAccessDenied:                "D",
	AceTypeSystemAudit:                 "AU",
	AceTypeSystemAlarm:                 "AL",
	AceTypeAccessAllowedCompound:       "",
	AceTypeAccessAllowedObject:         "OA",
	AceTypeAccessDeniedObject:          "OD",
	AceTypeSystemAuditObject:           "OU",
	AceTypeSystemAlarmObject:           "OL",
	AceTypeAccessAllowedCallback:       "XA",
	AceTypeAccessDeniedCallback:        "XD",
	AceTypeAccessAllowedCallbackObject: "",
	AceTypeAccessDeniedCallbackObject:  "",
	AceTypeSystemAuditCallback:         "XU",
	AceTypeSystemAlarmCallback:         "",
	AceTypeSystemAuditCallbackObject:   "",
	AceTypeSystemAlarmCallbackObject:   "",
}

var AceHeaderFlagsSDDL = map[ACEHeaderFlags]string{
	ACEHeaderFlagsObjectInheritAce:        "OI",
	ACEHeaderFlagsContainerInheritAce:     "CI",
	ACEHeaderFlagsNoPropogateInheritAce:   "NP",
	ACEHeaderFlagsInheritOnlyAce:          "IO",
	ACEHeaderFlagsInheritedAce:            "ID",
	ACEHeaderFlagsSuccessfulAccessAceFlag: "SA",
	ACEHeaderFlagsFailedAccessAceFlag:     "FA",
}

var OrderedFlags = map[string]int{
	"OI": 0,
	"CI": 1,
	"NP": 2,
	"IO": 3,
	"ID": 4,
	"SA": 5,
	"FA": 6,
}

var AceRightsSDDL = map[uint32]string{
	AccessMaskGenericRead:    "GR",
	AccessMaskGenericWrite:   "GW",
	AccessMaskGenericExecute: "GX",
	AccessMaskGenericAll:     "GA",
	AccessMaskWriteOwner:     "WO",
	AccessMaskWriteDACL:      "WD",
	AccessMaskReadControl:    "RC",
	AccessMaskDelete:         "SD",

	// Advanced ACEs
	ADSRightDSReadProp:      "RP",
	ADSRightDSWriteProp:     "WP",
	ADSRightDSCreateChild:   "CC",
	ADSRightDSDeleteChild:   "DC",
	ADSRightDSListChildrend: "LC",
	ADSRightDSSelf:          "SW",
	ADSRightDSListObject:    "LO",
	ADSRightDSDeleteTree:    "DT",
	ADSRightDSControlAccess: "CR",
}

var OrderedRights = map[string]int{
	"CC": 0,
	"DC": 1,
	"LC": 2,
	"SW": 3,
	"RP": 4,
	"WP": 5,
	"DT": 6,
	"LO": 7,
	"CR": 8,

	"SD": 9,
	"RC": 10,
	"WD": 11,
	"WO": 12,
	"GA": 13,
	"GX": 14,
	"GW": 15,
	"GR": 16,
}

var WellKnownSIDs = map[string]string{
	"S-1-1-0":      "WD",
	"S-1-3-0":      "CO",
	"S-1-3-1":      "CG",
	"S-1-5-2":      "NU",
	"S-1-5-4":      "IU",
	"S-1-5-6":      "SU",
	"S-1-5-7":      "AN",
	"S-1-5-9":      "ED",
	"S-1-5-10":     "PS",
	"S-1-5-11":     "AU",
	"S-1-5-12":     "RC",
	"S-1-5-18":     "SY",
	"S-1-5-19":     "LS",
	"S-1-5-20":     "NS",
	"S-1-5-32-544": "BA",
	"S-1-5-32-545": "BU",
	"S-1-5-32-546": "BG",
	"S-1-5-32-547": "PU",
	"S-1-5-32-548": "AO",
	"S-1-5-32-549": "SO",
	"S-1-5-32-550": "PO",
	"S-1-5-32-551": "BO",
	"S-1-5-32-552": "RE",
	"S-1-5-32-554": "RU",
	"S-1-5-32-555": "RD",
	"S-1-5-32-556": "NO",
	"S-1-5-32-558": "MY",
}

// https://docs.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-control
const (
	ControlDACLAutoInheritReq = 0x100
	ControlDACLAutoInherit    = 0x400
	ControlDACLProtected      = 0x1000
)

func (s ACE) RightsString() string {
	output := make([]string, len(OrderedRights))
	flags, _ := bamflags.ParseInt(int64(s.AccessMask.value))
	for _, flag := range flags {
		symbol := AceRightsSDDL[uint32(flag)]
		idx := OrderedRights[symbol]
		output[idx] = symbol
	}
	return strings.Join(output, "")
}

func (s ACEHeader) SDDLFlags() string {
	output := make([]string, len(OrderedFlags))
	flags, _ := bamflags.ParseInt(int64(s.Flags))
	// AceHeaderFlagsSDDL[s.Header.Flags], // AceFlags
	for _, flag := range flags {
		fType := ACEHeaderFlags(flag)
		symbol := AceHeaderFlagsSDDL[fType]
		idx := OrderedFlags[symbol]
		output[idx] = symbol
	}
	return strings.Join(output, "")
}

func (s ACE) ToSDDL() string {
	format := "(%s;%s;%s;%s;%s;%s)"

	var (
		objGUID          string
		inheritedObjGUID string
	)

	switch s.ObjectAce.(type) {
	case AdvancedAce:
		aa := s.ObjectAce.(AdvancedAce)
		objGUID = aa.ObjectType.String()
		inheritedObjGUID = aa.InheritedObjectType.String()
	}

	accountSID := s.ObjectAce.GetPrincipal().String()
	if wellKnown := WellKnownSIDs[accountSID]; wellKnown != "" {
		accountSID = wellKnown
	}

	sddlString := fmt.Sprintf(format,
		AceHeaderTypeSDDL[s.Header.Type], // AceType
		s.Header.SDDLFlags(),             // AceFlags
		s.RightsString(),                 // Rights
		objGUID,                          // ObjectGUID
		inheritedObjGUID,                 // Inherited Object GUID
		accountSID,                       // Account SID
		// "(attrs)",                        // Resource Attrs
	)
	return sddlString
}

func (a ACL) ToSDDL(flags string) string {
	sb := strings.Builder{}
	// TODO Change when SACLs are implemented
	sb.WriteString("D:")
	sb.WriteString(flags)
	for _, ace := range a.Aces {
		sb.WriteString(ace.ToSDDL())
	}
	return sb.String()
}

func (ndh NtSecurityDescriptorHeader) FlagString() string {
	// ControlDACLAutoInheritReq = 0x100 = AR
	// ControlDACLAutoInherit    = 0x400 = AI
	// ControlDACLProtected      = 0x1000 = P
	sb := strings.Builder{}

	ar, _ := bamflags.Contains(int64(ndh.Control), int64(ControlDACLAutoInheritReq))
	ai, _ := bamflags.Contains(int64(ndh.Control), int64(ControlDACLAutoInherit))
	p, _ := bamflags.Contains(int64(ndh.Control), int64(ControlDACLProtected))

	if ar {
		sb.WriteString("AR")
	}
	if ai {
		sb.WriteString("AI")
	}
	if p {
		sb.WriteString("AI")
	}

	return sb.String()
}

func (s NtSecurityDescriptor) ToSDDL() string {
	sb := strings.Builder{}
	fmt.Fprintf(&sb, "O:%s", s.Owner.String())
	fmt.Fprintf(&sb, "G:%s", s.Group.String())
	sb.WriteString(s.DACL.ToSDDL(s.Header.FlagString()))
	return sb.String()
}

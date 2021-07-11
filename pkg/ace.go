package winacl

import (
	"fmt"
	"strings"

	"github.com/audibleblink/bamflags"
)

type AceType byte

const (
	AceTypeAccessAllowed AceType = iota
	AceTypeAccessDenied
	AceTypeSystemAudit
	AceTypeSystemAlarm
	AceTypeAccessAllowedCompound
	AceTypeAccessAllowedObject
	AceTypeAccessDeniedObject
	AceTypeSystemAuditObject
	AceTypeSystemAlarmObject
	AceTypeAccessAllowedCallback
	AceTypeAccessDeniedCallback
	AceTypeAccessAllowedCallbackObject
	AceTypeAccessDeniedCallbackObject
	AceTypeSystemAuditCallback
	AceTypeSystemAlarmCallback
	AceTypeSystemAuditCallbackObject
	AceTypeSystemAlarmCallbackObject
)

var TypeLookup = map[AceType]string{
	AceTypeAccessAllowed:               "ACCESS_ALLOWED",
	AceTypeAccessDenied:                "ACCESS_DENIED",
	AceTypeSystemAudit:                 "SYSTEM_AUDIT",
	AceTypeSystemAlarm:                 "SYSTEM_ALARM",
	AceTypeAccessAllowedCompound:       "ACCESS_ALLOWED_COMPOUND",
	AceTypeAccessAllowedObject:         "ACCESS_ALLOWED_OBJECT",
	AceTypeAccessDeniedObject:          "ACCESS_DENIED_OBJECT",
	AceTypeSystemAuditObject:           "SYSTEM_AUDIT_OBJECT",
	AceTypeSystemAlarmObject:           "SYSTEM_ALARM_OBJECT",
	AceTypeAccessAllowedCallback:       "ACCESS_ALLOWED_CALLBACK",
	AceTypeAccessDeniedCallback:        "ACCESS_DENIED_CALLBACK",
	AceTypeAccessAllowedCallbackObject: "ACCESS_ALLOWED_CALLBACK_OBJECT",
	AceTypeAccessDeniedCallbackObject:  "ACCESS_DENIED_CALLBACK_OBJECT",
	AceTypeSystemAuditCallback:         "SYSTEM_AUDIT_CALLBACK",
	AceTypeSystemAlarmCallback:         "SYSTEM_ALARM_CALLBACK",
	AceTypeSystemAuditCallbackObject:   "SYSTEM_AUDIT_CALLBACK_OBJECT",
	AceTypeSystemAlarmCallbackObject:   "SYSTEM_ALARM_CALLBACK_OBJECT",
}

type ACEHeaderFlags byte

const (
	ACEHeaderFlagsObjectInheritAce        ACEHeaderFlags = 0x01
	ACEHeaderFlagsContainerInheritAce                    = 0x02
	ACEHeaderFlagsNoPropogateInheritAce                  = 0x04
	ACEHeaderFlagsInheritOnlyAce                         = 0x08
	ACEHeaderFlagsInheritedAce                           = 0x10
	ACEHeaderFlagsSuccessfulAccessAceFlag                = 0x40
	ACEHeaderFlagsFailedAccessAceFlag                    = 0x80
)

type ACEInheritanceFlags uint32

const (
	ACEInheritanceFlagsObjectTypePresent          ACEInheritanceFlags = 0x01
	ACEInheritanceFlagsInheritedObjectTypePresent                     = 0x02
)

type ACEAccessMask struct {
	value uint32
}

const (
	AccessMaskGenericRead    = 0x80000000
	AccessMaskGenericWrite   = 0x40000000
	AccessMaskGenericExecute = 0x20000000
	AccessMaskGenericAll     = 0x10000000
	AccessMaskMaximumAllowed = 0x02000000
	AccessMaskSystemSecurity = 0x01000000
	AccessMaskSynchronize    = 0x00100000
	AccessMaskWriteOwner     = 0x00080000
	AccessMaskWriteDACL      = 0x00040000
	AccessMaskReadControl    = 0x00020000
	AccessMaskDelete         = 0x00010000

	// Advances ACE Masks
	ADSRightDSControlAccess = 0x00000100
	ADSRightDSWriteProp     = 0x00000020
	ADSRightDSReadProp      = 0x00000010
	ADSRightDSSelf          = 0x00000008
	ADSRightDSDeleteChild   = 0x00000002
	ADSRightDSCreateChild   = 0x00000001
)

var MaskLookup = map[uint32]string{
	AccessMaskGenericRead:    "GENERIC_READ",
	AccessMaskGenericWrite:   "GENERIC_WRITE",
	AccessMaskGenericExecute: "GENERIC_EXECUTE",
	AccessMaskGenericAll:     "GENERIC_ALL",
	AccessMaskMaximumAllowed: "MAXIMUM_ALLOWED",
	AccessMaskSystemSecurity: "SYSTEM_SECURITY",
	AccessMaskSynchronize:    "SYNCHRONIZE",
	AccessMaskWriteOwner:     "WRITE_OWNER",
	AccessMaskWriteDACL:      "WRITE_DACL",
	AccessMaskReadControl:    "READ_CONTROL",
	AccessMaskDelete:         "DELETE",

	// Advanced ACEs
	ADSRightDSControlAccess: "CONTROL_ACCESS",
	ADSRightDSWriteProp:     "WRITE_PROP",
	ADSRightDSReadProp:      "READ_PROP",
	ADSRightDSSelf:          "SELF",
	ADSRightDSDeleteChild:   "DELETE_CHILD",
	ADSRightDSCreateChild:   "CREATE_CHILD",
}

func (am ACEAccessMask) Raw() uint32 {
	return am.value
}

func (am ACEAccessMask) String() string {
	sb := strings.Builder{}
	rights, _ := bamflags.ParseInt(int64(am.value))
	for _, right := range rights {
		if perm := MaskLookup[uint32(right)]; perm != "" {
			fmt.Fprintf(&sb, "%s ", perm)
		}
	}
	return sb.String()
}

//Header + AccessMask is 16 bytes
type ACE struct {
	Header     ACEHeader
	AccessMask ACEAccessMask
	ObjectAce  ObjectAce
}

func (s ACE) String() string {
	sb := strings.Builder{}
	aceType := s.GetTypeString()
	perms := s.AccessMask.String()

	switch s.ObjectAce.(type) {
	case BasicAce:
		sb.WriteString(fmt.Sprintf("SID: %v\n", s.ObjectAce.GetPrincipal()))
		sb.WriteString(fmt.Sprintf("AceType: %s\nPermissions: %v\nFlags: %v\n",
			aceType,
			perms,
			s.Header.Flags))
	case AdvancedAce:
		aa := s.ObjectAce.(AdvancedAce)
		sb.WriteString(
			fmt.Sprintf("SID: %v\nAceType: %s\nPermissions: %s\nObjectType: %v\nInheritedObjectType: %v\nFlags: %v\n",
				aa.GetPrincipal(),
				aceType,
				perms,
				aa.ObjectType,
				aa.InheritedObjectType,
				aa.Flags))
	}

	return sb.String()
}

type ACEHeader struct {
	Type  AceType
	Flags byte
	Size  uint16
}

//This is a GUID
type ACEObjectType struct {
	PartA uint32
	PartB uint16
	PartC uint16
	PartD [8]byte
}

func (s ACE) GetType() AceType {
	return s.Header.Type
}

func (s ACE) GetTypeString() string {
	return TypeLookup[s.Header.Type]
}

type BasicAce struct {
	SecurityIdentifier SID
}

func (s BasicAce) GetPrincipal() SID {
	return s.SecurityIdentifier
}

type AdvancedAce struct {
	Flags               uint32 //4 bytes
	ObjectType          GUID   //16 bytes
	InheritedObjectType GUID
	SecurityIdentifier  SID
}

func (s AdvancedAce) GetPrincipal() SID {
	return s.SecurityIdentifier
}

type ObjectAce interface {
	GetPrincipal() SID
}

type AccessAllowedAce BasicAce
type AccessDeniedAce BasicAce
type SystemAuditAce BasicAce
type SystemAlarmAce BasicAce

// No idea what this actually is and it doesn't appear to be documented anywhere
type AccessAllowedCompoundAce struct{}

type AccessAllowedObjectAce AdvancedAce
type AccessDeniedObjectAce AdvancedAce
type SystemAuditObjectAce AdvancedAce
type SystemAlarmObjectAce AdvancedAce
type AccessAllowedCallbackAce BasicAce
type AccessDeniedCallbackAce BasicAce
type AccessAllowedCallbackObjectAce AdvancedAce
type AccessDeniedCallbackObjectAce AdvancedAce
type SystemAuditCallbackAce BasicAce
type SystemAlarmCallbackAce BasicAce
type SystemAuditCallbackObjectAce AdvancedAce
type SystemAlarmCallbackObjectAce AdvancedAce

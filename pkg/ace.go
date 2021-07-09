package winacl

import (
	"fmt"
	"strings"
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

type ACEAccessMask uint32

//Header + AccessMask is 16 bytes
type ACE struct {
	Header     ACEHeader
	AccessMask ACEAccessMask
	ObjectAce  ObjectAce
}

func (s ACE) String() string {
	sb := strings.Builder{}
	sb.WriteString(fmt.Sprintf("AceType: %s. AccessMask: %v. Flags: %v\n",
		s.GetTypeString(),
		s.AccessMask,
		s.Header.Flags))
	switch s.ObjectAce.(type) {
	case BasicAce:
		sb.WriteString(fmt.Sprintf("SID: %v\n", s.ObjectAce.GetPrincipal()))
	case AdvancedAce:
		aa := s.ObjectAce.(AdvancedAce)
		sb.WriteString(
			fmt.Sprintf("SID: %v. ObjectType: %v. InheritedObjectType: %v. Flags: %v\n",
				aa.GetPrincipal(),
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

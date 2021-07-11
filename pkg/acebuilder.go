package winacl

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

func NewAce(buf *bytes.Buffer) ACE {
	ace := ACE{}

	ace.Header = NewACEHeader(buf)
	binary.Read(buf, binary.LittleEndian, &ace.AccessMask.value)
	switch ace.Header.Type {
	case AceTypeAccessAllowed, AceTypeAccessDenied, AceTypeSystemAudit, AceTypeSystemAlarm, AceTypeAccessAllowedCallback, AceTypeAccessDeniedCallback, AceTypeSystemAuditCallback, AceTypeSystemAlarmCallback:
		ace.ObjectAce = NewBasicAce(buf, ace.Header.Size)
	case AceTypeAccessAllowedObject, AceTypeAccessDeniedObject, AceTypeSystemAuditObject, AceTypeSystemAlarmObject, AceTypeAccessAllowedCallbackObject, AceTypeAccessDeniedCallbackObject, AceTypeSystemAuditCallbackObject, AceTypeSystemAlarmCallbackObject:
		ace.ObjectAce = NewAdvancedAce(buf, ace.Header.Size)
	}

	return ace
}

func NewACEHeader(buf *bytes.Buffer) ACEHeader {
	header := ACEHeader{}
	binary.Read(buf, binary.LittleEndian, &header.Type)
	binary.Read(buf, binary.LittleEndian, &header.Flags)
	binary.Read(buf, binary.LittleEndian, &header.Size)
	return header
}

func NewBasicAce(buf *bytes.Buffer, totalSize uint16) BasicAce {
	oa := BasicAce{}

	if sid, err := NewSID(buf, int(totalSize-8)); err != nil {
		fmt.Printf("Error reading sid: %v\n", err)
	} else {
		oa.SecurityIdentifier = sid
	}
	return oa
}

func NewAdvancedAce(buf *bytes.Buffer, totalSize uint16) AdvancedAce {
	oa := AdvancedAce{}
	binary.Read(buf, binary.LittleEndian, &oa.Flags)
	offset := 12
	if (oa.Flags & (ACEInheritanceFlagsObjectTypePresent)) != 0 {
		oa.ObjectType = NewGUID(buf)
		offset += 16
	}

	if (oa.Flags & (ACEInheritanceFlagsInheritedObjectTypePresent)) != 0 {
		oa.InheritedObjectType = NewGUID(buf)
		offset += 16
	}

	// Header+AccessMask is 16 bytes, other members are 36 bytes.
	if sid, err := NewSID(buf, int(totalSize)-offset); err != nil {
		fmt.Printf("Error reading sid: %v\n", err)
	} else {
		oa.SecurityIdentifier = sid
	}
	return oa
}

package winacl

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

func ParseAce(buf *bytes.Buffer) ACE {
	ace := ACE{}

	ace.Header = ReadACEHeader(buf)
	binary.Read(buf, binary.LittleEndian, &ace.AccessMask)
	switch ace.Header.Type {
	case AceTypeAccessAllowed, AceTypeAccessDenied, AceTypeSystemAudit, AceTypeSystemAlarm, AceTypeAccessAllowedCallback, AceTypeAccessDeniedCallback, AceTypeSystemAuditCallback, AceTypeSystemAlarmCallback:
		ace.ObjectAce = ReadBasicAce(buf, ace.Header.Size)
	case AceTypeAccessAllowedObject, AceTypeAccessDeniedObject, AceTypeSystemAuditObject, AceTypeSystemAlarmObject, AceTypeAccessAllowedCallbackObject, AceTypeAccessDeniedCallbackObject, AceTypeSystemAuditCallbackObject, AceTypeSystemAlarmCallbackObject:
		ace.ObjectAce = ReadAdvancedAce(buf, ace.Header.Size)
	}

	return ace
}

func ReadACEHeader(buf *bytes.Buffer) ACEHeader {
	header := ACEHeader{}
	binary.Read(buf, binary.LittleEndian, &header.Type)
	binary.Read(buf, binary.LittleEndian, &header.Flags)
	binary.Read(buf, binary.LittleEndian, &header.Size)
	return header
}

func ReadBasicAce(buf *bytes.Buffer, totalSize uint16) BasicAce {
	oa := BasicAce{}

	if sid, err := ReadSID(buf, int(totalSize-8)); err != nil {
		fmt.Printf("Error reading sid: %v\n", err)
	} else {
		oa.SecurityIdentifier = sid
	}
	return oa
}

func ReadAdvancedAce(buf *bytes.Buffer, totalSize uint16) AdvancedAce {
	oa := AdvancedAce{}
	binary.Read(buf, binary.LittleEndian, &oa.Flags)
	offset := 12
	if (oa.Flags & uint32(ACEInheritanceFlagsObjectTypePresent)) != 0 {
		oa.ObjectType = ReadGUID(buf)
		offset += 16
	}

	if (oa.Flags & uint32(ACEInheritanceFlagsInheritedObjectTypePresent)) != 0 {
		oa.InheritedObjectType = ReadGUID(buf)
		offset += 16
	}

	// Header+AccessMask is 16 bytes, other members are 36 bytes.
	if sid, err := ReadSID(buf, int(totalSize)-offset); err != nil {
		fmt.Printf("Error reading sid: %v\n", err)
	} else {
		oa.SecurityIdentifier = sid
	}
	return oa
}

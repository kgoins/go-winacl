package winacl

import (
	"bytes"
	"encoding/binary"
)

type NtSecurityDescriptorHeader struct {
	Revision    byte
	Sbz1        byte
	Control     uint16
	OffsetOwner uint32
	OffsetGroup uint32
	OffsetSacl  uint32
	OffsetDacl  uint32
}

const (
	DACLAutoInheritReq = 0x0100
	DACLAutoInherited  = 0x0400
	SACLAutoInherited  = 0x0800
	DACLProtected      = 0x1000
)

func NewNTSDHeader(buf *bytes.Buffer) NtSecurityDescriptorHeader {
	var descriptor = NtSecurityDescriptorHeader{}

	binary.Read(buf, binary.LittleEndian, &descriptor.Revision)
	binary.Read(buf, binary.LittleEndian, &descriptor.Sbz1)
	binary.Read(buf, binary.LittleEndian, &descriptor.Control)
	binary.Read(buf, binary.LittleEndian, &descriptor.OffsetOwner)
	binary.Read(buf, binary.LittleEndian, &descriptor.OffsetGroup)
	binary.Read(buf, binary.LittleEndian, &descriptor.OffsetSacl)
	binary.Read(buf, binary.LittleEndian, &descriptor.OffsetDacl)

	return descriptor
}

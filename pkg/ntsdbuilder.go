package winacl

import (
	"bytes"
	"encoding/binary"
)

func ParseNtSecurityDescriptor(ntSecurityDescriptorBytes []byte) (NtSecurityDescriptor, error) {
	var buf = bytes.NewBuffer(ntSecurityDescriptorBytes)
	ntsd := NtSecurityDescriptor{}
	ntsd.Header = ReadNTSDHeader(buf)
	ntsd.DACL = ReadACL(buf)

	return ntsd, nil
}

func ReadNTSDHeader(buf *bytes.Buffer) NtSecurityDescriptorHeader {
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

func ReadACLHeader(buf *bytes.Buffer) ACLHeader {
	var header = ACLHeader{}
	binary.Read(buf, binary.LittleEndian, &header.Revision)
	binary.Read(buf, binary.LittleEndian, &header.Sbz1)
	binary.Read(buf, binary.LittleEndian, &header.Size)
	binary.Read(buf, binary.LittleEndian, &header.AceCount)
	binary.Read(buf, binary.LittleEndian, &header.Sbz2)

	return header
}

func ReadACL(buf *bytes.Buffer) ACL {
	acl := ACL{}
	acl.Header = ReadACLHeader(buf)
	acl.Aces = make([]ACE, 0, acl.Header.AceCount)

	for i := 0; i < int(acl.Header.AceCount); i++ {
		ace := ParseAce(buf)
		acl.Aces = append(acl.Aces, ace)
	}

	return acl
}

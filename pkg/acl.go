package winacl

import (
	"bytes"
	"encoding/binary"
)

type ACL struct {
	Header ACLHeader
	Aces   []ACE
}

type ACLHeader struct {
	Revision byte
	Sbz1     byte
	Size     uint16
	AceCount uint16
	Sbz2     uint16
}

func NewACLHeader(buf *bytes.Buffer) ACLHeader {
	var header = ACLHeader{}
	binary.Read(buf, binary.LittleEndian, &header.Revision)
	binary.Read(buf, binary.LittleEndian, &header.Sbz1)
	binary.Read(buf, binary.LittleEndian, &header.Size)
	binary.Read(buf, binary.LittleEndian, &header.AceCount)
	binary.Read(buf, binary.LittleEndian, &header.Sbz2)

	return header
}

func NewACL(buf *bytes.Buffer) ACL {
	acl := ACL{}
	acl.Header = NewACLHeader(buf)
	acl.Aces = make([]ACE, 0, acl.Header.AceCount)

	for i := 0; i < int(acl.Header.AceCount); i++ {
		ace := NewAce(buf)
		acl.Aces = append(acl.Aces, ace)
	}

	return acl
}

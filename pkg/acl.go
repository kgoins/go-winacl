package winacl

import (
	"bytes"
	"encoding/binary"
)

// ACL represents an Access Control List
type ACL struct {
	Header ACLHeader
	Aces   []ACE
}

// ACLHeader represents an Access Control List's Header
type ACLHeader struct {
	Revision byte
	Sbz1     byte
	Size     uint16
	AceCount uint16
	Sbz2     uint16
}

// NewACLHeader is a constructor that will parse out an ACLHeader from a byte buffer
func NewACLHeader(buf *bytes.Buffer) ACLHeader {
	var header = ACLHeader{}
	binary.Read(buf, binary.LittleEndian, &header.Revision)
	binary.Read(buf, binary.LittleEndian, &header.Sbz1)
	binary.Read(buf, binary.LittleEndian, &header.Size)
	binary.Read(buf, binary.LittleEndian, &header.AceCount)
	binary.Read(buf, binary.LittleEndian, &header.Sbz2)

	return header
}

// NewACL is a constructor that will parse out an ACL from a byte buffer
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

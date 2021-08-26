package winacl

import (
	"bytes"
	"fmt"
)

// NtSecurityDescriptor represent a Security Descriptor
type NtSecurityDescriptor struct {
	Header NtSecurityDescriptorHeader
	DACL   ACL
	SACL   ACL
	Owner  SID
	Group  SID
}

// String will returns general information about itself
// See also: ToSDDL()
func (s NtSecurityDescriptor) String() string {
	return fmt.Sprintf(
		"Parsed Security Descriptor:\n Offsets:\n Owner=%v Group=%v Sacl=%v Dacl=%v\n",
		s.Header.OffsetOwner,
		s.Header.OffsetGroup,
		s.Header.OffsetDacl,
		s.Header.OffsetSacl,
	)
}

// NewNtSecurityDescriptor is a constructor that will parse out an
// NtSecurityDescriptor from a byte buffer
func NewNtSecurityDescriptor(ntsdBytes []byte) (NtSecurityDescriptor, error) {
	var buf = bytes.NewBuffer(ntsdBytes)
	var err error

	ntsd := NtSecurityDescriptor{}
	ntsd.Header, err = NewNTSDHeader(buf)
	if err != nil {
		return ntsd, err
	}

	ntsd.DACL, err = NewACL(buf)
	if err != nil {
		return ntsd, err
	}

	sidSize := ntsd.Header.OffsetGroup - ntsd.Header.OffsetOwner

	// it seems that sometimes the owner and group are at the front of the bytes
	// stream as well as being part of the first ACE. or something like that...
	if sidSize == 0 {
		ntsd.Owner = ntsd.DACL.Aces[0].ObjectAce.GetPrincipal()
		ntsd.Group = ntsd.DACL.Aces[0].ObjectAce.GetPrincipal()
		return ntsd, nil
	}
	ntsd.Owner, err = NewSID(buf, int(sidSize))
	if err != nil {
		return ntsd, err
	}
	ntsd.Group, err = NewSID(buf, int(sidSize))
	return ntsd, err
}

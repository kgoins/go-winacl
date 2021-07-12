package winacl

import (
	"bytes"
	"fmt"
)

type NtSecurityDescriptor struct {
	Header NtSecurityDescriptorHeader
	DACL   ACL
	SACL   ACL
	Owner  SID
	Group  SID
}

func (s NtSecurityDescriptor) String() string {
	return fmt.Sprintf(
		"Parsed Security Descriptor:\n Offsets:\n Owner=%v Group=%v Sacl=%v Dacl=%v\n",
		s.Header.OffsetOwner,
		s.Header.OffsetGroup,
		s.Header.OffsetDacl,
		s.Header.OffsetSacl,
	)
}

func NewNtSecurityDescriptor(ntsdBytes []byte) (NtSecurityDescriptor, error) {
	var buf = bytes.NewBuffer(ntsdBytes)
	var err error
	ntsd := NtSecurityDescriptor{}
	ntsd.Header = NewNTSDHeader(buf)
	ntsd.DACL = NewACL(buf)
	sidSize := ntsd.Header.OffsetGroup - ntsd.Header.OffsetOwner
	ntsd.Owner, err = NewSID(buf, int(sidSize))
	if err != nil {
		return ntsd, err
	}
	ntsd.Group, err = NewSID(buf, int(sidSize))
	return ntsd, err
}

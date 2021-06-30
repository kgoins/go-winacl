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
	ntsd := NtSecurityDescriptor{}
	ntsd.Header = NewNTSDHeader(buf)
	ntsd.DACL = NewACL(buf)

	return ntsd, nil
}

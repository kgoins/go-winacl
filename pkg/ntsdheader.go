package winacl

import (
	"bytes"
	"encoding/binary"

	"github.com/audibleblink/bamflags"
	"golang.org/x/sys/windows"
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

type NtsdDefaultedFlags struct {
	OwnerDefaulted bool
	GroupDefaulted bool
	DACLDefaulted  bool
	SACLDefaulted  bool
}

// Ref: https://docs.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-setsecuritydescriptordacl
func (h NtSecurityDescriptorHeader) GetDefaultedFlagsFromControl() (f NtsdDefaultedFlags, err error) {
	f.OwnerDefaulted, err = bamflags.Contains(int64(h.Control), windows.SE_OWNER_DEFAULTED)
	if err != nil {
		return
	}

	f.GroupDefaulted, err = bamflags.Contains(int64(h.Control), windows.SE_GROUP_DEFAULTED)
	if err != nil {
		return
	}

	f.SACLDefaulted, err = bamflags.Contains(int64(h.Control), windows.SE_SACL_DEFAULTED)
	if err != nil {
		return
	}

	f.DACLDefaulted, err = bamflags.Contains(int64(h.Control), windows.SE_DACL_DEFAULTED)
	if err != nil {
		return
	}

	return
}

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

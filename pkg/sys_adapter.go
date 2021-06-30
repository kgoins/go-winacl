package winacl

import "golang.org/x/sys/windows"

func BuildSysSID(sid SID) (*windows.SID, error) {
	sidStr := sid.String()
	return windows.StringToSid(sidStr)
}

func GetTrusteeFromAce(ace ACE) (t windows.TRUSTEE, err error) {
	sid := ace.ObjectAce.GetPrincipal()
	sysSID, err := BuildSysSID(sid)
	if err != nil {
		return
	}

	t.TrusteeForm = windows.TRUSTEE_IS_SID
	t.TrusteeType = windows.TRUSTEE_IS_UNKNOWN
	t.TrusteeValue = windows.TrusteeValueFromSID(sysSID)

	return
}

func BuildSysAce(ace ACE) (sysACE windows.EXPLICIT_ACCESS, err error) {
	trustee, err := GetTrusteeFromAce(ace)
	if err != nil {
		return
	}

	sysACE.AccessPermissions = ace.AccessMask
	sysACE.AccessMode = windows.ACCESS_MODE(ace.Header.Type)
	sysACE.Inheritance = uint32(ace.Header.Flags)
	sysACE.Trustee = trustee

	return
}

func BuildSysAcl(acl ACL) (*windows.ACL, error) {
	sysAces := make([]windows.EXPLICIT_ACCESS, 0, len(acl.Aces))

	for _, ace := range acl.Aces {
		sysAce, err := BuildSysAce(ace)
		if err != nil {
			return nil, err
		}

		sysAces = append(sysAces, sysAce)
	}

	return windows.ACLFromEntries(sysAces, nil)
}

func BuildSysNtsd(ntsd NtSecurityDescriptor) (secDesc *windows.SECURITY_DESCRIPTOR, err error) {
	secDesc, err = windows.NewSecurityDescriptor()
	if err != nil {
		return
	}

	err = secDesc.SetControl(
		windows.SECURITY_DESCRIPTOR_CONTROL(ntsd.Header.Control),
		windows.SECURITY_DESCRIPTOR_CONTROL(ntsd.Header.Control),
	)
	if err != nil {
		return
	}

	defaultedFlags, err := ntsd.Header.GetDefaultedFlagsFromControl()
	if err != nil {
		return
	}

	err = secDesc.SetGroup(&ntsd.Group, defaultedFlags.GroupDefaulted)
	if err != nil {
		return
	}

	err = secDesc.SetOwner(&ntsd.Owner, defaultedFlags.OwnerDefaulted)
	if err != nil {
		return
	}

	sacl, err := BuildSysAcl(ntsd.SACL)
	if err != nil {
		return
	}

	err = secDesc.SetSACL(sacl, (sacl == nil), defaultedFlags.SACLDefaulted)
	if err != nil {
		return
	}

	dacl, err := BuildSysAcl(ntsd.DACL)
	if err != nil {
		return
	}

	err = secDesc.SetDACL(dacl, (dacl == nil), defaultedFlags.DACLDefaulted)
	if err != nil {
		return
	}

	return
}

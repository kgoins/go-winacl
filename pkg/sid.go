package winacl

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"regexp"
	"strings"
)

// WellKnownSIDsRE is a map of common Windows SIDs, as regex
// patterns, mapped to their corresponding description
var WellKnownSIDsRE = map[string]string{
	"S-1-5-[0-9-]+-500":     "Administrator",
	"S-1-5-[0-9-]+-501":     "Guest",
	"S-1-5-[0-9-]+-502":     "KRBTGT",
	"S-1-5-[0-9-]+-512":     "Domain Admins",
	"S-1-5-[0-9-]+-513":     "Domain Users",
	"S-1-5-[0-9-]+-514":     "Domain Guests",
	"S-1-5-[0-9-]+-515":     "Domain Computers",
	"S-1-5-[0-9-]+-516":     "Domain Controllers",
	"S-1-5-[0-9-]+-517":     "Cert Publishers",
	"S-1-5-[0-9-]+-520":     "Group Policy Creator Owners",
	"S-1-5-[0-9-]+-533":     "RAS and IAS Servers",
	"S-1-5-5-[0-9]+-[0-9]+": "Logon Session",
	"S-1-5-21-[0-9-]+-518":  "Schema Admins",
	"S-1-5-21-[0-9-]+-519":  "Enterprise Admins",
	"S-1-5-21-[0-9-]+-553":  "RAS Servers",
}

// WellKnownSIDs is a map of common Windows SIDs mapped to
// their corresponding description
var WellKnownSIDs = map[string]string{
	"S-1-0":        "Null Authority",
	"S-1-0-0":      "Nobody",
	"S-1-1":        "World Authority",
	"S-1-1-0":      "Everyone",
	"S-1-2":        "Local Authority",
	"S-1-2-0":      "Local (Users with the ability to log in locally)",
	"S-1-2-1":      "Console Logon (Users who are logged onto the physical console)",
	"S-1-3":        "Creator Authority",
	"S-1-3-0":      "Creator Owner",
	"S-1-3-1":      "Creator Group",
	"S-1-3-2":      "Creator Owner Server",
	"S-1-3-3":      "Creator Group Server",
	"S-1-3-4":      "Owner Rights",
	"S-1-4":        "Non-unique Authority",
	"S-1-5":        "NT Authority",
	"S-1-5-1":      "Dialup",
	"S-1-5-2":      "Network",
	"S-1-5-3":      "Batch",
	"S-1-5-4":      "Interactive",
	"S-1-5-6":      "Service",
	"S-1-5-7":      "Anonymous",
	"S-1-5-8":      "Proxy",
	"S-1-5-9":      "Enterprise Domain Controllers",
	"S-1-5-10":     "Principal Self",
	"S-1-5-11":     "Authenticated Users",
	"S-1-5-12":     "Restricted Code",
	"S-1-5-13":     "Terminal Server Users",
	"S-1-5-14":     "Remote Interactive Logon",
	"S-1-5-15":     "This Organization",
	"S-1-5-17":     "This Organization (Used by the default IIS user)",
	"S-1-5-18":     "Local System",
	"S-1-5-19":     "NT Authority",
	"S-1-5-20":     "NT Authority",
	"S-1-5-32-544": "Administrators",
	"S-1-5-32-545": "Users",
	"S-1-5-32-546": "Guests",
	"S-1-5-32-547": "Power Users",
	"S-1-5-32-548": "Account Operators",
	"S-1-5-32-549": "Server Operators",
	"S-1-5-32-550": "Print Operators",
	"S-1-5-32-551": "Backup Operators",
	"S-1-5-32-552": "Replicators",
	"S-1-5-32-554": "BUILTIN\\Pre-Windows 2000 Compatible Access",
	"S-1-5-32-555": "BUILTIN\\Remote Desktop Users",
	"S-1-5-32-556": "BUILTIN\\Network Configuration Operators",
	"S-1-5-32-557": "BUILTIN\\Incoming Forest Trust Builders",
	"S-1-5-32-558": "BUILTIN\\Performance Monitor Users",
	"S-1-5-32-559": "BUILTIN\\Performance Log Users",
	"S-1-5-32-560": "BUILTIN\\Windows Authorization Access Group",
	"S-1-5-32-561": "BUILTIN\\Terminal Server License Servers",
	"S-1-5-32-562": "BUILTIN\\Distributed COM Users",
	"S-1-5-32-568": "BUILTIN\\IIS IUSRS",
	"S-1-5-32-569": "Cryptographic Operators",
	"S-1-5-32-573": "BUILTIN\\Event Log Readers",
	"S-1-5-32-574": "BUILTIN\\Certificate Service DCOM Access",
	"S-1-5-33":     "Write Restricted",
	"S-1-5-64-10":  "NTLM Authentication",
	"S-1-5-64-14":  "SChannel Authentication",
	"S-1-5-64-21":  "Digest Authentication",
	"S-1-5-80":     "NT Service",
	"S-1-5-86-1544737700-199408000-2549878335-3519669259-381336952": "WMI (Local Service)",
	"S-1-5-86-615999462-62705297-2911207457-59056572-3668589837":    "WMI (Network Service)",
	"S-1-5-1000":   "Other Organization",
	"S-1-16-0":     "Untrusted Mandatory Level",
	"S-1-16-4096":  "Low Mandatory Level",
	"S-1-16-8192":  "Medium Mandatory Level",
	"S-1-16-8448":  "Medium Plus Mandatory Level",
	"S-1-16-12288": "High Mandatory Level",
	"S-1-16-16384": "System Mandatory Level",
	"S-1-16-20480": "Protected Process Mandatory Level",
	"S-1-16-28672": "Secure Process Mandatory Level",
	"S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464": "TrustedInstaller",
}

// SID represent a SID in its parts
type SID struct {
	Revision       byte
	NumAuthorities byte
	Authority      []byte
	SubAuthorities []uint32
}

// String returns the human-readable SID
func (s SID) String() string {
	var sb strings.Builder

	if len(s.Authority) < 6 {
		return ""
	}

	fmt.Fprintf(&sb, "S-%v-%v", s.Revision, int(s.Authority[5]))
	for i := 0; i < int(s.NumAuthorities); i++ {
		fmt.Fprintf(&sb, "-%v", s.SubAuthorities[i])
	}

	return sb.String()
}

// NewSID is a constructor that will parse out a SID from a byte buffer
func NewSID(buf *bytes.Buffer, sidLength int) (SID, error) {
	sid := SID{}
	data := buf.Next(sidLength)

	if revision := data[0]; revision != 1 {
		return sid, SIDInvalidError{"invalid SID revision"}
	} else if numAuth := data[1]; numAuth > 15 {
		return sid, SIDInvalidError{"invalid number of subauthorities"}
	} else if ((int(numAuth) * 4) + 8) < len(data) {
		return sid, SIDInvalidError{"invalid SID length"}
	} else {
		authority := data[2:8]
		subAuth := make([]uint32, numAuth)
		for i := 0; i < int(numAuth); i++ {
			offset := 8 + (i * 4)
			subAuth[i] = binary.LittleEndian.Uint32(data[offset : offset+4])
		}

		sid.Revision = revision
		sid.Authority = authority
		sid.NumAuthorities = numAuth
		sid.SubAuthorities = subAuth

		return sid, nil
	}
}

// Resolve will return the human readable description of a SID
// If one does not exist, it will return in the normal "S-!-" notation
func (s SID) Resolve() string {
	s1 := s.String()
	resolved := WellKnownSIDs[s1]

	if resolved == "" {
		for pattern, name := range WellKnownSIDsRE {
			match, _ := regexp.MatchString(pattern, s1)
			if match {
				return name
			}
		}
	} else if resolved != "" {
		return resolved
	}
	return s1
}

type SIDInvalidError struct{ msg string }

func (e SIDInvalidError) Error() string {
	return fmt.Sprintf("NewSID: %s", e.msg)
}

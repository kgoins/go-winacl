package winacl

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
)

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

	sb.WriteString(fmt.Sprintf(
		"S-%v-%v",
		s.Revision,
		int(s.Authority[5]),
	))

	for i := 0; i < int(s.NumAuthorities); i++ {
		sb.WriteString(fmt.Sprintf("-%v", s.SubAuthorities[i]))
	}

	return sb.String()
}

// NewSID is a constructor that will parse out a SID from a byte buffer
func NewSID(buf *bytes.Buffer, sidLength int) (SID, error) {
	sid := SID{}
	data := buf.Next(sidLength)

	if revision := data[0]; revision != 1 {
		return sid, errors.New("invalid SID revision")
	} else if numAuth := data[1]; numAuth > 15 {
		return sid, errors.New("invalid number of subauthorities")
	} else if ((int(numAuth) * 4) + 8) < len(data) {
		return sid, errors.New("invalid sid length")
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

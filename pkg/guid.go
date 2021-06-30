package winacl

import (
	"bytes"
	"encoding/binary"
)

type GUID struct {
	Data1 uint32
	Data2 uint16
	Data3 uint16
	Data4 [8]byte
}

func NewGUID(buf *bytes.Buffer) GUID {
	guid := GUID{}
	binary.Read(buf, binary.LittleEndian, &guid.Data1)
	binary.Read(buf, binary.LittleEndian, &guid.Data2)
	binary.Read(buf, binary.LittleEndian, &guid.Data3)
	binary.Read(buf, binary.LittleEndian, &guid.Data4)
	return guid
}

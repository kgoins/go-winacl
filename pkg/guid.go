package winacl

import (
	"bytes"
	"encoding/binary"

	"golang.org/x/sys/windows"
)

func ReadGUID(buf *bytes.Buffer) windows.GUID {
	guid := windows.GUID{}
	binary.Read(buf, binary.LittleEndian, &guid.Data1)
	binary.Read(buf, binary.LittleEndian, &guid.Data2)
	binary.Read(buf, binary.LittleEndian, &guid.Data3)
	binary.Read(buf, binary.LittleEndian, &guid.Data4)
	return guid
}

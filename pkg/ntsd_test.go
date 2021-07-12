package winacl_test

import (
	"encoding/base64"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	winacl "github.com/kgoins/go-winacl/pkg"
	"github.com/stretchr/testify/require"
)

func getTestNtsdBytes() ([]byte, error) {
	testFile := filepath.Join(getTestDataDir(), "ntsd.b64")
	testBytes, err := ioutil.ReadFile(testFile)
	if err != nil {
		return testBytes, err
	}
	return base64.StdEncoding.DecodeString(string(testBytes))
}

func getTestNtsdSDDLTestString() (string, error) {
	testFile := filepath.Join(getTestDataDir(), "ntsd.sddl")
	sddl, err := os.ReadFile(testFile)
	return string(sddl), err
}

func newTestSD() winacl.NtSecurityDescriptor {
	ntsdBytes, _ := getTestNtsdBytes()
	ntsd, _ := winacl.NewNtSecurityDescriptor(ntsdBytes)
	return ntsd
}

func TestBuildNTSD(t *testing.T) {
	r := require.New(t)

	ntsdBytes, err := getTestNtsdBytes()
	r.NoError(err)

	ntsd, err := winacl.NewNtSecurityDescriptor(ntsdBytes)
	r.NoError(err)

	dacl := ntsd.DACL
	r.NotNil(dacl)
	r.Equal(int(dacl.Header.AceCount), len(dacl.Aces))
}

func TestToSDDL(t *testing.T) {
	r := require.New(t)
	sddl, _ := getTestNtsdSDDLTestString()
	ntsd := newTestSD()
	r.Equal(sddl, ntsd.ToSDDL())
}

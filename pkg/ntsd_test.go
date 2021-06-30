package winacl_test

import (
	"encoding/base64"
	"io/ioutil"
	"path/filepath"
	"testing"

	winacl "github.com/kgoins/go-winacl/pkg"
	"github.com/stretchr/testify/require"
)

func getTestNtsdBytes() ([]byte, error) {
	testFile := filepath.Join(getTestDataDir(), "ntsd.b64")
	testBytes, err := ioutil.ReadFile(testFile)
	if err != nil {
		return nil, err
	}

	return base64.StdEncoding.DecodeString(string(testBytes))
}

func TestBuildNTSD(t *testing.T) {
	r := require.New(t)

	ntsdBytes, err := getTestNtsdBytes()
	r.NoError(err)

	ntsd, err := winacl.NewNtSecurityDescriptor(ntsdBytes)
	r.NoError(err)

	dacl := ntsd.DACL
	r.NotNil(dacl)
	r.Equal(dacl.Header.AceCount, len(dacl.Aces))
}

func TestGetSDDL(t *testing.T) {
	r := require.New(t)

	ntsdBytes, err := getTestNtsdBytes()
	r.NoError(err)

	ntsd, err := winacl.NewNtSecurityDescriptor(ntsdBytes)
	r.NoError(err)

	sddl, err := ntsd.GetSDDL()
	r.NoError(err)
	r.NotEmpty(sddl)
}

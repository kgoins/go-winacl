package winacl_test

import (
	"encoding/base64"
	"io/ioutil"
	"path/filepath"
	"testing"

	winacl "github.com/kgoins/go-winacl/pkg"
	"github.com/stretchr/testify/require"
)

func TestBuildNTSD(t *testing.T) {
	r := require.New(t)

	testFile := filepath.Join(getTestDataDir(), "ntsd.b64")
	testBytes, err := ioutil.ReadFile(testFile)
	r.NoError(err)

	ntsdBytes, err := base64.StdEncoding.DecodeString(string(testBytes))
	r.NoError(err)

	ntsd, err := winacl.NewNtSecurityDescriptor(ntsdBytes)
	r.NoError(err)

	dacl := ntsd.DACL
	r.NotNil(dacl)
	r.Equal(dacl.Header.AceCount, len(dacl.Aces))
}

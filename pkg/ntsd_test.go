package winacl_test

import (
	"testing"

	winacl "github.com/kgoins/go-winacl/pkg"
	"github.com/stretchr/testify/require"
)

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

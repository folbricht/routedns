package rdns

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCurrentBuild(t *testing.T) {
	defer func(v, c, d string) {
		BuildVersion, BuildCommit, BuildTime = v, c, d
	}(BuildVersion, BuildCommit, BuildTime)

	// Values injected at link time win over anything the toolchain embedded.
	// The version can pick up a "+dirty" suffix when the tree is modified.
	BuildVersion, BuildCommit, BuildTime = "v1.2.3", "abc123", "2026-01-01T00:00:00Z"
	b := CurrentBuild()
	require.True(t, strings.HasPrefix(b.Version, "v1.2.3"), b.Version)
	require.Equal(t, "abc123", b.Commit)
	require.Equal(t, "2026-01-01T00:00:00Z", b.Date)

	// Without them there is still a version to report, from the build info the
	// toolchain embeds. This is the 'go install' and local-build case.
	BuildVersion, BuildCommit, BuildTime = "", "", ""
	require.NotEmpty(t, CurrentBuild().Version)
}

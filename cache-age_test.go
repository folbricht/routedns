package rdns

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// A record timestamped ahead of now has to count as new rather than wrapping
// into a huge age. The Redis backend used to convert a negative float to
// uint32 here, which made a record stored a minute in the future measure as
// 4294967237 seconds old, past every TTL, so nothing written by a machine
// whose clock ran ahead could be served.
func TestCacheAgeIgnoresTimestampsInTheFuture(t *testing.T) {
	now := time.Now().UnixNano()
	require.Zero(t, cacheAge(now, now+int64(time.Minute)))
	require.Equal(t, uint32(60), cacheAge(now, now-int64(time.Minute)))
}

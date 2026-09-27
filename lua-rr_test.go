//go:build !nolua

package rdns

import (
	"errors"
	"reflect"
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

// Every record type the dns library knows has to be describable, so a
// dependency bump that adds a field shape the bindings cannot handle fails
// here. It used to panic while the package loaded instead, which took down
// every process, not only those running a script.
func TestBuildRRDBCoversEveryType(t *testing.T) {
	db, err := buildRRDB()
	require.NoError(t, err)
	require.Len(t, db, len(dns.TypeToRR))
}

// A field the bindings have no accessor for is reported rather than panicked on.
func TestRRFieldsForTypeRejectsUnsupportedField(t *testing.T) {
	type unsupportedRR struct {
		Hdr    dns.RR_Header
		Weight float64
	}

	require.NotPanics(t, func() {
		fields, err := rrFieldsForType(reflect.TypeFor[unsupportedRR](), nil)
		require.Nil(t, fields)
		require.ErrorContains(t, err, "unsupported RR field value type float64")
		require.ErrorContains(t, err, "unsupportedRR")
	})
}

// A database that cannot be built fails the group that asked for it, rather
// than the process. Nothing can make the real one fail today, so the failure
// is injected.
func TestLuaSurfacesRRDBError(t *testing.T) {
	original := loadRRDB
	loadRRDB = func() (rrFieldDB, error) { return nil, errors.New("injected build failure") }
	t.Cleanup(func() { loadRRDB = original })

	_, err := NewLua("test-lua", LuaOptions{Script: `function Resolve(msg, ci) return nil, nil end`})
	require.ErrorContains(t, err, "injected build failure")
}

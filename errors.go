package rdns

import (
	"fmt"
)

// QueryTimeoutError is returned when a query times out.
//
// It carries the name that was asked for rather than the query itself: a query
// that timed out may still be on its way to the connection, so the message it
// was built from is no longer the caller's to read.
type QueryTimeoutError struct {
	name string
}

func (e QueryTimeoutError) Error() string {
	return fmt.Sprintf("query for '%s' timed out", e.name)
}

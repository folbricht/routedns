package rdns

import (
	"fmt"

	"github.com/miekg/dns"
)

// QueryTimeoutError is returned when a query times out.
type QueryTimeoutError struct {
	query *dns.Msg
}

func (e QueryTimeoutError) Error() string {
	return fmt.Sprintf("query for '%s' timed out", qName(e.query))
}

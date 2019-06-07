package rdns

import "fmt"

// Listener is an interface for a DNS listener.
type Listener interface {
	Start() error
	fmt.Stringer
}

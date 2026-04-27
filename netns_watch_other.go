//go:build !linux

package rdns

import "fmt"

type NetNSState int

const (
	NetNSAbsent NetNSState = iota
	NetNSPresent
)

func SubscribeNetNS(name string) (<-chan NetNSState, func(), error) {
	return nil, nil, fmt.Errorf("network namespaces are only supported on Linux")
}

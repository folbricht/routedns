//go:build !linux

package rdns

import (
	"fmt"
	"time"
)

type NetNSState int

const (
	NetNSAbsent NetNSState = iota
	NetNSPresent
)

func SubscribeNetNS(name string) (<-chan NetNSState, func(), error) {
	return nil, nil, fmt.Errorf("network namespaces are only supported on Linux")
}

func WaitNetNSReady(name string, timeout time.Duration) error {
	return fmt.Errorf("network namespaces are only supported on Linux")
}

//go:build !linux

package rdns

import (
	"fmt"
	"syscall"
)

func (s SocketOptions) dialerControl() func(string, string, syscall.RawConn) error {
	if !s.active() {
		return nil
	}
	return func(string, string, syscall.RawConn) error {
		return fmt.Errorf("socket options (fwmark, bind-interface) are only supported on Linux")
	}
}

func (s SocketOptions) applyToConn(conn any) error {
	if !s.active() {
		return nil
	}
	return fmt.Errorf("socket options (fwmark, bind-interface) are only supported on Linux")
}

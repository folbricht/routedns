//go:build !linux

package rdns

import (
	"errors"
	"io/fs"
)

// XSocketServerOptions contain settings for the xsocket fd-server. The server
// relies on Linux-specific facilities (network namespaces, SCM_RIGHTS fd
// passing into a namespace), so it is unsupported elsewhere.
type XSocketServerOptions struct {
	Unrestricted bool
	SocketMode   fs.FileMode
}

// XSocketServer is only supported on Linux, see xsocketserver_linux.go.
type XSocketServer struct {
	path string
}

func NewXSocketServer(path string, opt XSocketServerOptions) *XSocketServer {
	return &XSocketServer{path: path}
}

func (s *XSocketServer) String() string {
	return "XSocketServer(" + s.path + ")"
}

func (s *XSocketServer) Start() error {
	return errors.New("the xsocket fd-server is only supported on Linux")
}

func (s *XSocketServer) Stop() error {
	return nil
}

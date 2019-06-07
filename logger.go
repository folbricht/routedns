package rdns

// Log can be used to set the logger used by the library.
var Log Logger = Silent{}

// Logger allows the use of custom loggers in the FUSE server. The log.Logger
// in the standard library implements this interface.
type Logger interface {
	Println(v ...interface{})
	Printf(format string, v ...interface{})
}

// Silent logger that implements the Logger interface. Produces no output.
type Silent struct{}

// Println is a NOP, needed to implement the Logger interface.
func (Silent) Println(...interface{}) {}

// Printf is a NOP, needed to implement the Logger interface.
func (Silent) Printf(string, ...interface{}) {}

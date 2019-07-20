package rdns

import "github.com/sirupsen/logrus"

// Log is a package-global logger used throughout the library. Configuration can be
// changed directly on this instance or the instance replaced.
var Log = logrus.New()

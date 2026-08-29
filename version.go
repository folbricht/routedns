package rdns

import "runtime/debug"

// Populated at link time by goreleaser, for example
//
//	-X github.com/folbricht/routedns.BuildVersion=v0.1.241
//
// They are empty for 'go install' and for local builds, where the values come
// from the build information the toolchain embeds instead. These have to stay
// plain string variables without an initializer: the linker's -X flag cannot
// set a variable whose value comes from a function call.
var (
	BuildVersion string
	BuildTime    string
	BuildCommit  string
)

// BuildInfo describes the running binary.
type BuildInfo struct {
	Version string
	Commit  string
	Date    string
}

// CurrentBuild describes the running binary, preferring the values injected at
// link time and falling back to what the toolchain embedded. A module
// installed with 'go install' carries its version, and a build from a checkout
// carries the revision and its timestamp, so only a build from a source
// tarball has nothing to report.
func CurrentBuild() BuildInfo {
	b := BuildInfo{
		Version: BuildVersion,
		Commit:  BuildCommit,
		Date:    BuildTime,
	}

	// Whether the version was injected at link time rather than derived below.
	linked := b.Version != ""

	if bi, ok := debug.ReadBuildInfo(); ok {
		if b.Version == "" {
			b.Version = bi.Main.Version
		}
		var modified bool
		for _, s := range bi.Settings {
			switch s.Key {
			case "vcs.revision":
				if b.Commit == "" {
					b.Commit = s.Value
				}
			case "vcs.time":
				if b.Date == "" {
					b.Date = s.Value
				}
			case "vcs.modified":
				modified = s.Value == "true"
			}
		}
		// Built from a tree with uncommitted changes, which is worth knowing
		// when the version is quoted in a bug report. Only needed for a linked
		// version, since the toolchain already marks a derived one.
		if modified && linked {
			b.Version += "+dirty"
		}
	}

	if b.Version == "" {
		b.Version = "unknown"
	}
	return b
}

package rdns

import (
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/miekg/dns"
)

type BlocklistDB interface {
	// Reload initializes a new instance of the same database but with
	// a new ruleset loaded.
	Reload() (BlocklistDB, error)

	// Returns true if the question matches a rule. If the IP is not nil,
	// respond with the given IP. NXDOMAIN otherwise. The returned names,
	// if set, are used to answer PTR queries
	Match(msg *dns.Msg) (ip []net.IP, names []string, m *BlocklistMatch, matched bool)

	fmt.Stringer
}

// BlocklistMatch is returned by blocklists when a match is found. It contains
// information about what rule matched, what list it was from etc. Used mostly
// for logging.
type BlocklistMatch struct {
	List string // Identifier or name of the blocklist
	Rule string // Identifier for the rule that matched
}

func (m *BlocklistMatch) GetList() string {
	if m == nil {
		return "none"
	}
	return m.List
}

func (m *BlocklistMatch) GetRule() string {
	if m == nil {
		return "none"
	}
	return m.Rule
}

// A database that builds a new instance of itself with a freshly loaded
// ruleset. Both the name-based and the IP-based databases do, which is what
// lets one refresh loop serve every blocklist component.
type reloadable[T any] interface {
	Reload() (T, error)
}

// Reloads a database on an interval until the process ends, swapping the new
// one in under the given lock. Databases that hold resources, such as the
// memory-mapped location databases, are closed after the swap rather than
// before: queries match under a read-lock, so none can still be using the old
// one once the write-lock was acquired.
func refreshDatabase[T reloadable[T]](id, what string, refresh time.Duration, mu *sync.RWMutex, db *T) {
	log := Log.With("id", id)
	for {
		time.Sleep(refresh)
		log.Debug("reloading " + what)
		reloaded, err := (*db).Reload()
		if err != nil {
			log.Warn("failed to load rules, continuing with the ones already loaded",
				"error", err)
			closeDatabase(reloaded) // those rules are already being served
			continue
		}
		mu.Lock()
		old := *db
		*db = reloaded
		mu.Unlock()
		closeDatabase(old)
	}
}

// closeDatabase releases what a database holds, for those that hold anything:
// the location databases own a memory-mapped file, the rest own nothing.
func closeDatabase[T any](db T) {
	if closer, ok := any(db).(io.Closer); ok {
		closer.Close()
	}
}

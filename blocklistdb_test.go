package rdns

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

// refreshDatabase runs until the process ends, which in a test means until the
// package's last test does. A gate lets a finished test leave its loop blocked
// in Reload rather than reloading every millisecond for the rest of the run.
type gate struct {
	closed atomic.Bool
	block  chan struct{} // never closed, so a receive parks the caller
}

// Opens a gate for the duration of the test.
func openGate(t *testing.T) *gate {
	t.Helper()
	g := &gate{block: make(chan struct{})}
	t.Cleanup(func() { g.closed.Store(true) })
	return g
}

func (g *gate) pass() {
	if g.closed.Load() {
		<-g.block
	}
}

// A blocklist database that counts reloads and hands out a new instance every
// time, so a test can watch the swap happen.
type countingDB struct {
	generation int
	reloads    *atomic.Int64
	closes     *atomic.Int64
	failReload bool
	gate       *gate
}

func (d *countingDB) Reload() (BlocklistDB, error) {
	d.gate.pass()
	d.reloads.Add(1)
	if d.failReload {
		return nil, errors.New("no rules today")
	}
	return &countingDB{generation: d.generation + 1, reloads: d.reloads, closes: d.closes, gate: d.gate}, nil
}

func (d *countingDB) Match(*dns.Msg) ([]net.IP, []string, *BlocklistMatch, bool) {
	return nil, nil, nil, false
}
func (d *countingDB) String() string { return "countingDB" }

// closingDB additionally holds a resource, as the location databases do, and
// records whether this instance in particular was closed.
type closingDB struct {
	countingDB
	closed atomic.Bool
}

func (d *closingDB) Reload() (BlocklistDB, error) {
	d.gate.pass()
	d.reloads.Add(1)
	next := &closingDB{}
	next.generation = d.generation + 1
	next.reloads = d.reloads
	next.closes = d.closes
	next.gate = d.gate
	return next, nil
}

func (d *closingDB) Close() error {
	d.closed.Store(true)
	d.closes.Add(1)
	return nil
}

// The reloaded database replaces the one in use.
func TestRefreshDatabaseSwaps(t *testing.T) {
	var reloads, closes atomic.Int64
	var mu sync.RWMutex
	var db BlocklistDB = &countingDB{reloads: &reloads, closes: &closes, gate: openGate(t)}

	go refreshDatabase("test", "blocklist", time.Millisecond, &mu, &db)

	require.Eventually(t, func() bool {
		mu.RLock()
		defer mu.RUnlock()
		return db.(*countingDB).generation > 2
	}, time.Second, time.Millisecond)

	// Nothing to close on a database that holds no resources.
	require.Zero(t, closes.Load())
}

// A database holding a resource is closed, but only after it has been replaced.
func TestRefreshDatabaseClosesReplaced(t *testing.T) {
	var reloads, closes atomic.Int64
	var mu sync.RWMutex
	first := &closingDB{}
	first.reloads = &reloads
	first.closes = &closes
	first.gate = openGate(t)
	var db BlocklistDB = first

	go refreshDatabase("test", "blocklist", time.Millisecond, &mu, &db)

	require.Eventually(t, func() bool { return closes.Load() > 2 }, time.Second, time.Millisecond)
	require.True(t, first.closed.Load(), "the replaced database was not closed")

	// Only databases that were swapped out get closed, never the live one.
	mu.RLock()
	defer mu.RUnlock()
	require.False(t, db.(*closingDB).closed.Load(), "the database in use was closed")
}

// A database that fails to reload stays in use and the loop keeps trying.
func TestRefreshDatabaseKeepsFailedDatabase(t *testing.T) {
	var reloads, closes atomic.Int64
	var mu sync.RWMutex
	original := &countingDB{reloads: &reloads, closes: &closes, failReload: true, gate: openGate(t)}
	var db BlocklistDB = original

	go refreshDatabase("test", "blocklist", time.Millisecond, &mu, &db)

	require.Eventually(t, func() bool { return reloads.Load() > 2 }, time.Second, time.Millisecond)

	mu.RLock()
	defer mu.RUnlock()
	require.Same(t, original, db)
}

// A source that cannot be read holds the rules it has while the sources beside
// it carry on refreshing. Only when none of them can be read is there nothing
// to swap in.
func TestMultiDBReloadUnchanged(t *testing.T) {
	dir := t.TempDir()
	name := filepath.Join(dir, "list.txt")
	require.NoError(t, os.WriteFile(name, []byte("gone.example.com\n"), 0644))

	failing := NewFileLoader(name, FileLoaderOptions{AllowFailure: true})
	unreadable, err := NewDomainDB("unreadable", failing)
	require.NoError(t, err)
	steady, err := NewDomainDB("steady", NewStaticLoader([]string{"kept.example.com"}))
	require.NoError(t, err)

	multi, err := NewMultiDB(unreadable, steady)
	require.NoError(t, err)

	// The file is gone, so that source reports nothing to change. The group
	// still reloads, and both sets of rules still match.
	require.NoError(t, os.Remove(name))
	reloaded, err := multi.Reload()
	require.NoError(t, err, "one unreadable source must not stall the group")
	for _, q := range []string{"gone.example.com.", "kept.example.com."} {
		msg := new(dns.Msg)
		msg.SetQuestion(q, dns.TypeA)
		_, _, _, ok := reloaded.Match(msg)
		require.True(t, ok, "query %s", q)
	}

	// With every source unreadable there is nothing new to install.
	onlyFailing, err := NewMultiDB(unreadable)
	require.NoError(t, err)
	_, err = onlyFailing.Reload()
	require.ErrorIs(t, err, errBlocklistUnchanged)
}

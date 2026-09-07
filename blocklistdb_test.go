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

// A rule the database will not take is a failure like any other. With
// AllowFailure a list that has never loaded starts empty rather than keeping
// the process from starting; once it has loaded, the rules it is serving stay.
func TestBlocklistRuleErrorAllowFailure(t *testing.T) {
	dir := t.TempDir()
	name := filepath.Join(dir, "list.txt")
	require.NoError(t, os.WriteFile(name, []byte("a*b.example.com\n"), 0644))

	loader := NewFileLoader(name, FileLoaderOptions{AllowFailure: true})
	db, err := NewDomainDB("testlist", loader)
	require.NoError(t, err, "a rule the database refuses must not keep it from starting")
	msg := new(dns.Msg)
	msg.SetQuestion("ab.example.com.", dns.TypeA)
	_, _, _, ok := db.Match(msg)
	require.False(t, ok, "a list that failed to load must hold none of it")

	require.NoError(t, os.WriteFile(name, []byte("good.example.com\n"), 0644))
	reloaded, err := db.Reload()
	require.NoError(t, err)

	// The list has loaded now, so a rule the database refuses is an error and
	// the rules already serving are what stays.
	require.NoError(t, os.WriteFile(name, []byte("a*b.example.com\n"), 0644))
	_, err = reloaded.Reload()
	require.Error(t, err, "a list the database refused must not pass as loaded")
}

// A source that cannot be read holds the rules it has while the sources beside
// it carry on refreshing.
func TestMultiDBReloadUnreadableSource(t *testing.T) {
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

	// The file is gone, so that source fails to load. The group still
	// reloads, and both sets of rules still match.
	require.NoError(t, os.Remove(name))
	reloaded, err := multi.Reload()
	require.NoError(t, err, "one unreadable source must not stall the group")
	for _, q := range []string{"gone.example.com.", "kept.example.com."} {
		msg := new(dns.Msg)
		msg.SetQuestion(q, dns.TypeA)
		_, _, _, ok := reloaded.Match(msg)
		require.True(t, ok, "query %s", q)
	}

	// With every source unreadable the group still reloads, holding the rules
	// each of its sources already had.
	onlyFailing, err := NewMultiDB(unreadable)
	require.NoError(t, err)
	kept, err := onlyFailing.Reload()
	require.NoError(t, err)
	msg := new(dns.Msg)
	msg.SetQuestion("gone.example.com.", dns.TypeA)
	_, _, _, ok := kept.Match(msg)
	require.True(t, ok, "the group dropped the rules it was serving")
}

// The IP group behaves like the name-based one: a source that cannot be read
// keeps its rules while the sources beside it refresh.
func TestMultiIPDBReloadUnreadableSource(t *testing.T) {
	dir := t.TempDir()
	name := filepath.Join(dir, "list.txt")
	require.NoError(t, os.WriteFile(name, []byte("10.0.0.0/8\n"), 0644))

	failing := NewFileLoader(name, FileLoaderOptions{AllowFailure: true})
	unreadable, err := NewCidrDB("unreadable", failing)
	require.NoError(t, err)
	steady, err := NewCidrDB("steady", NewStaticLoader([]string{"192.168.0.0/16"}))
	require.NoError(t, err)

	multi, err := NewMultiIPDB(unreadable, steady)
	require.NoError(t, err)

	require.NoError(t, os.Remove(name))
	reloaded, err := multi.Reload()
	require.NoError(t, err, "one unreadable source must not stall the group")
	for _, ip := range []string{"10.1.2.3", "192.168.1.1"} {
		_, ok := reloaded.Match(net.ParseIP(ip))
		require.True(t, ok, "address %s", ip)
	}

	// With every source unreadable the group still reloads, holding the rules
	// each of its sources already had.
	onlyFailing, err := NewMultiIPDB(unreadable)
	require.NoError(t, err)
	kept, err := onlyFailing.Reload()
	require.NoError(t, err)
	_, ok := kept.Match(net.ParseIP("10.1.2.3"))
	require.True(t, ok, "the group dropped the rules it was serving")
}

// A database that owns something closing releases, as the location databases
// own their memory-mapped file. Its list never reads, so every reload hands
// the rules on in a new instance.
type handleIPDB struct {
	ip     net.IP
	closed bool
	broken bool        // cannot hand its rules on, as a lost map file leaves it
	next   *handleIPDB // what the last reload handed on to
}

func (m *handleIPDB) Reload() (IPBlocklistDB, error) {
	if m.broken {
		return nil, errors.New("the list could not be read")
	}
	m.next = &handleIPDB{ip: m.ip}
	return m.next, errors.New("the list could not be read")
}

func (m *handleIPDB) Match(ip net.IP) (*BlocklistMatch, bool) {
	if m.closed {
		panic("matched against a database that was closed")
	}
	return &BlocklistMatch{List: "handle"}, ip.Equal(m.ip)
}

func (m *handleIPDB) Close() error {
	m.closed = true
	return nil
}

func (m *handleIPDB) String() string { return "handle" }

// The group is closed once the group replacing it is in place, so what it
// hands on has to be a database of its own rather than one it is about to
// close.
func TestMultiIPDBOwnershipOnReload(t *testing.T) {
	owner := &handleIPDB{ip: net.ParseIP("10.0.0.1")}
	steady, err := NewCidrDB("steady", NewStaticLoader([]string{"192.168.0.0/16"}))
	require.NoError(t, err)
	multi, err := NewMultiIPDB(owner, steady)
	require.NoError(t, err)

	reloaded, err := multi.Reload()
	require.NoError(t, err, "one unreadable source must not stall the group")
	carried := owner.next
	require.NotNil(t, carried, "the group dropped what its database handed on")

	require.NoError(t, multi.Close())
	require.True(t, owner.closed, "the old group left its own database open")
	require.False(t, carried.closed, "the old group closed the database it handed on")

	_, ok := reloaded.Match(net.ParseIP("10.0.0.1"))
	require.True(t, ok, "the rules handed on are not being served")
}

// A group that cannot hand its rules on hands back nothing, so the group
// around it keeps what it has rather than installing an empty one.
func TestMultiIPDBNestedFailure(t *testing.T) {
	inner, err := NewMultiIPDB(&handleIPDB{ip: net.ParseIP("10.0.0.1"), broken: true})
	require.NoError(t, err)
	steady, err := NewCidrDB("steady", NewStaticLoader([]string{"192.168.0.0/16"}))
	require.NoError(t, err)
	outer, err := NewMultiIPDB(inner, steady)
	require.NoError(t, err)

	reloaded, err := outer.Reload()
	require.Error(t, err)
	require.Nil(t, reloaded, "an empty group must not pass as the rules already loaded")
}

package rdns

import (
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

// A blocklist database that counts reloads and hands out a new instance every
// time, so a test can watch the swap happen.
type countingDB struct {
	generation int
	reloads    *atomic.Int64
	closes     *atomic.Int64
	failReload bool
}

func (d *countingDB) Reload() (BlocklistDB, error) {
	d.reloads.Add(1)
	if d.failReload {
		return nil, errors.New("no rules today")
	}
	return &countingDB{generation: d.generation + 1, reloads: d.reloads, closes: d.closes}, nil
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
	d.reloads.Add(1)
	next := &closingDB{}
	next.generation = d.generation + 1
	next.reloads = d.reloads
	next.closes = d.closes
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
	var db BlocklistDB = &countingDB{reloads: &reloads, closes: &closes}

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
	original := &countingDB{reloads: &reloads, closes: &closes, failReload: true}
	var db BlocklistDB = original

	go refreshDatabase("test", "blocklist", time.Millisecond, &mu, &db)

	require.Eventually(t, func() bool { return reloads.Load() > 2 }, time.Second, time.Millisecond)

	mu.RLock()
	defer mu.RUnlock()
	require.Same(t, original, db)
}

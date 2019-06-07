package rdns

import (
	"crypto/tls"
	"fmt"
	"os"
	"sync"

	"github.com/miekg/dns"
)

// DoTClient is a DNS-over-TLS resolver.
type DoTClient struct {
	endpoint string
	conn     *tlsConn
}

var _ Resolver = &DoTClient{}

// NewDoTClient instantiates a new DNS-over-TLS resolver.
func NewDoTClient(endpoint string) *DoTClient {
	return &DoTClient{
		endpoint: endpoint,
		conn:     newTLSConn(endpoint),
	}
}

// Resolve a DNS query.
func (d *DoTClient) Resolve(q *dns.Msg) (*dns.Msg, error) {
	return d.conn.resolve(q)
}

func (d *DoTClient) String() string {
	return fmt.Sprintf("DoT(%s)", d.endpoint)
}

// Connection multiplexing and piplining queries on an upsteam TLS DNS connections.
type tlsConn struct {
	endpoint string
	requests chan *request
	conn     *dns.Conn
}

func newTLSConn(endpoint string) *tlsConn {
	c := &tlsConn{
		endpoint: endpoint,
		requests: make(chan *request),
	}
	go c.start()
	return c
}

// Resolve a single query using this connection.
func (c *tlsConn) resolve(q *dns.Msg) (*dns.Msg, error) {
	r := newRequest(q)
	c.requests <- r
	return r.waitFor()
}

// Starts a loop that will wait for queries and open an upstream connection on-demand, writing queries
// and reading answers concurrently using the same connection. It also handles errors like idle
// close from upstream.
func (c *tlsConn) start() {
	var (
		wg       sync.WaitGroup
		inFlight inFlightQueue
	)
	for req := range c.requests { // Lazy connection. Only open a real connection if there's a request
		done := make(chan struct{})
		Log.Println("opening dot connection to", c.endpoint)
		conn, err := dns.DialWithTLS("tcp", c.endpoint, &tls.Config{})
		if err != nil {
			Log.Println("failed to open dot connection to", c.endpoint, ":", err)
			req.markDone(nil, err)
			continue
		}
		wg.Add(2)

		go func() { c.requests <- req }() // re-queue the request that triggered the upstream connection

		go func() { // writer
			for {
				select {
				case req := <-c.requests:
					query := inFlight.add(req)
					Log.Printf("sending query for '%s' to %s", qName(query), c.endpoint)
					if err := conn.WriteMsg(query); err != nil {
						req.markDone(nil, err)
						conn.Close() // throw away this connection, should wake up the reader as well
						wg.Done()
						Log.Printf("failed to send query for '%s' to %s : %s", qName(query), c.endpoint, err.Error())
						return
					}
				case <-done: // the reader ran into an error and we want to stop using this connection
					wg.Done()
					return
				}
			}
		}()
		go func() { // reader
			for {
				a, err := conn.ReadMsg()
				if err != nil {
					close(done) // tell the writer to not use this connection anymore
					wg.Done()
					Log.Println("dot connection to", c.endpoint, "terminated")
					return
				}
				req := inFlight.get(a) // match the answer to an in-flight query
				if req == nil {
					fmt.Fprintln(os.Stderr, "unexpected answer received:", a)
					continue
				}
				req.markDone(a, nil)
			}
		}()

		// wait for both, sender and receiver to terminate before trying to reconnect
		wg.Wait()
	}
}

// Request received from a client. It also contains the response and a channel that is
// closed when the request is done.
type request struct {
	q, a *dns.Msg
	err  error
	done chan struct{}
}

func newRequest(q *dns.Msg) *request {
	return &request{
		q:    q,
		done: make(chan struct{}),
	}
}

// Wait for the request to be completed and return the answer.
func (r *request) waitFor() (*dns.Msg, error) {
	<-r.done

	// As per https://tools.ietf.org/html/rfc7858#section-3.3, we need to double check this
	// really is the correct response.
	if len(r.a.Question) > 0 && len(r.q.Question) > 0 {
		q := r.q.Question[0]
		a := r.a.Question[0]
		if a.Name != q.Name || a.Qclass != q.Qclass || a.Qtype != q.Qtype {
			return nil, fmt.Errorf("expected answer for %s, got %s", q.String(), a.String())
		}
	}

	return r.a, r.err
}

// Mark the request as complete.
func (r *request) markDone(a *dns.Msg, err error) {
	if a != nil {
		a.Id = r.q.Id // Fix the query ID in the answer to match the query
	}
	r.a = a
	r.err = err
	close(r.done)
}

// Queue to manage requests that are in flight. Used to asynchronously match received
// responses with their requests.
type inFlightQueue struct {
	requests  map[uint16]*request
	mu        sync.Mutex
	idCounter uint16
}

// Add a request to the queue and return an updated DNS query with a new ID. The ID needs
// to be unique per connection, and we could be receiving multiple queries with the same
// ID. So make up a new ID, used that in the query upstream, then map it back to the
// request and replace the ID with the original one.
func (q *inFlightQueue) add(r *request) *dns.Msg {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.requests == nil {
		q.requests = make(map[uint16]*request)
	}
	q.idCounter++
	q.requests[q.idCounter] = r
	query := r.q.Copy()
	query.Id = q.idCounter
	return query
}

// Returns the request for a given query ID, or nil if the request isn't in the queue. The
// request is removed from the queue.
func (q *inFlightQueue) get(a *dns.Msg) *request {
	q.mu.Lock()
	defer q.mu.Unlock()
	id := a.Id
	r, ok := q.requests[id]
	if !ok {
		return nil
	}
	delete(q.requests, id)
	return r
}

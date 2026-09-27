package rdns

import (
	"sync"

	"github.com/miekg/dns"
)

// Buffer pool for encoding messages into wire format, used by anything on the
// query path that has to pack one: the cache backends storing a record, and
// the listeners that pack an answer themselves rather than letting the dns
// library do it.
var packBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, 0, 2048)
		return &b
	},
}

func putPackBuf(bufPtr *[]byte) {
	*bufPtr = (*bufPtr)[:0]
	packBufPool.Put(bufPtr)
}

// adoptPackBuf keeps a buffer that outgrew the pooled one, so the pool adapts
// to the workload rather than reallocating for every large answer.
func adoptPackBuf(bufPtr *[]byte, encoded []byte) {
	if cap(encoded) > cap(*bufPtr) {
		*bufPtr = encoded
	}
}

// packToPool packs a message into a buffer from the pool. The wire format it
// returns aliases that buffer, so the caller has to be done reading it before
// handing the buffer back with putPackBuf. Nothing is handed back on an error.
func packToPool(a *dns.Msg) (wire []byte, bufPtr *[]byte, err error) {
	bufPtr = packBufPool.Get().(*[]byte)
	wire, err = a.PackBuffer((*bufPtr)[:cap(*bufPtr)])
	if err != nil {
		putPackBuf(bufPtr)
		return nil, nil, err
	}
	adoptPackBuf(bufPtr, wire)
	return wire, bufPtr, nil
}

// putPackBufAfterWrite hands a buffer back only when the write that consumed it
// reported success. A failed write can leave the transport holding the bytes: a
// HTTP/2 handler whose connection goes away mid-write returns while the frame is
// still queued, and a QUIC stream that is reset leaves the data with the sender.
// Recycling the buffer then would let the next answer packed into it go out in
// place of the one the transport still means to send.
func putPackBufAfterWrite(bufPtr *[]byte, err error) {
	if err == nil {
		putPackBuf(bufPtr)
	}
}

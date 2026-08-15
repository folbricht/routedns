package rdns

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/miekg/dns"
)

// The raw cache file stores entries in the form the cache already holds them,
// so writing is a copy and reading needs no parsing:
//
//	header:  magic, then a version byte
//	record:  uint32 length, then the blob, repeated to end of file
//
// The magic starts with a NUL so it can't be mistaken for the JSON format,
// whose records start with '{', and so anything that opens the file can see
// at once that it is binary.
//
// The version belongs to the file rather than to each record: it is checked
// once, and a file cannot hold a mix. The version byte inside a blob stays
// reserved for a record that travels on its own, without a file around it.
const (
	rawCacheMagic     = "\x00RDC"
	rawCacheVersion   = 1
	rawCacheHeaderLen = len(rawCacheMagic) + 1

	// An upper bound on a stored record, so a corrupt length can't ask for an
	// unbounded allocation. A DNS message is capped at 64KB by the protocol
	// and the key adds a few hundred bytes at most.
	maxRawCacheRecord = dns.MaxMsgSize + 1024
)

// isRawCacheFile reports whether the reader is positioned at a raw cache file,
// leaving it unread either way so the right decoder can take it from the top.
func isRawCacheFile(r *bufio.Reader) bool {
	magic, err := r.Peek(len(rawCacheMagic))
	return err == nil && string(magic) == rawCacheMagic
}

func (c *lruCache) serializeRaw(w io.Writer) error {
	header := make([]byte, 0, rawCacheHeaderLen)
	header = append(header, rawCacheMagic...)
	header = append(header, rawCacheVersion)
	if _, err := w.Write(header); err != nil {
		return err
	}

	var length [4]byte
	for item := c.tail.prev; item != c.head; item = item.prev {
		if len(item.blob) > maxRawCacheRecord {
			// Can't be framed, and can't have been stored either.
			continue
		}
		binary.BigEndian.PutUint32(length[:], uint32(len(item.blob)))
		if _, err := w.Write(length[:]); err != nil {
			return err
		}
		if _, err := w.Write(item.blob); err != nil {
			return err
		}
	}
	return nil
}

// deserializeRaw reads a raw cache file. A record that can't be used is
// skipped, as in the JSON format. Damage to the framing is different: there is
// no way to find the next record once a length is untrustworthy, so reading
// stops there and keeps the entries it already has.
func (c *lruCache) deserializeRaw(r io.Reader) error {
	header := make([]byte, rawCacheHeaderLen)
	if _, err := io.ReadFull(r, header); err != nil {
		return fmt.Errorf("failed to read cache file header: %w", err)
	}
	if string(header[:len(rawCacheMagic)]) != rawCacheMagic {
		return errors.New("not a raw cache file")
	}
	if version := header[len(rawCacheMagic)]; version != rawCacheVersion {
		return fmt.Errorf("unsupported raw cache file version %d", version)
	}

	var length [4]byte
	for {
		if _, err := io.ReadFull(r, length[:]); err != nil {
			if errors.Is(err, io.EOF) {
				return nil // clean end of file
			}
			Log.Warn("cache file ends mid-record, keeping the entries read so far", "error", err)
			return nil
		}

		n := binary.BigEndian.Uint32(length[:])
		if n < blobHdrLen || n > maxRawCacheRecord {
			Log.Warn("cache file record has an implausible length, stopping", "length", n)
			return nil
		}

		blob := make(cacheBlob, n)
		if _, err := io.ReadFull(r, blob); err != nil {
			Log.Warn("cache file ends mid-record, keeping the entries read so far", "error", err)
			return nil
		}

		key, ok := blobFromFile(blob)
		if !ok {
			continue // skip the record, the framing is still good
		}
		c.addKey(key, blob)
	}
}

// blobFromFile checks a blob read from disk far enough to be sure the
// accessors on it are safe, and returns the key it is stored under.
func blobFromFile(blob cacheBlob) (lruKey, bool) {
	if len(blob) < blobHdrLen ||
		blobHdrLen+blob.netLen()+blob.nameLen() > len(blob) {
		return lruKey{}, false
	}
	// Unpack once here so a corrupt message is kept out of the cache rather
	// than taking up an entry until the lookup that finds it evicts it.
	if err := new(dns.Msg).Unpack(blob.message()); err != nil {
		return lruKey{}, false
	}
	key := blob.key()
	if key.Question.Name == "" {
		return lruKey{}, false
	}
	return key, true
}

package rdns

import "github.com/miekg/dns"

//  QueryPaddingBlockSize is used to pad queries sent over DoT and DoH according to rfc8467
const QueryPaddingBlockSize = 128

//  ResponsePaddingBlockSize is used to pad responses over DoT and DoH according to rfc8467
const ResponsePaddingBlockSize = 468

// Fixed buffers to draw on for padding (rather than allocate every time)
var respPadBuf [ResponsePaddingBlockSize]byte
var queryPadBuf [QueryPaddingBlockSize]byte

// Add padding to an answer before it's sent back over DoH or DoT according to rfc8467.
// Don't call this for un-encrypted responses as they should not be padded.
func padAnswer(q, a *dns.Msg) {
	edns0q := q.IsEdns0()
	if edns0q == nil { // Don't pad if the client does not support EDNS0
		return
	}

	// Add an OPT record to the answer if there isn't one already
	edns0a := a.IsEdns0()
	if edns0a == nil {
		a.SetEdns0(edns0q.UDPSize(), edns0q.Do())
		edns0a = a.IsEdns0()
	}

	// If the answer has padding, grab that and truncate it before re-calculating the length
	var paddingOpt *dns.EDNS0_PADDING
	for _, opt := range edns0a.Option {
		if opt.Option() == dns.EDNS0PADDING {
			paddingOpt = opt.(*dns.EDNS0_PADDING)
			paddingOpt.Padding = nil
		}
	}

	// Add the padding option if there isn't one already
	if paddingOpt == nil {
		paddingOpt = new(dns.EDNS0_PADDING)
		edns0a.Option = append(edns0a.Option, paddingOpt)
	}

	// Calculate the desired padding length
	len := a.Len()
	padLen := ResponsePaddingBlockSize - len%ResponsePaddingBlockSize

	// If padding would make the packet larger than the request EDNS0 allows, we need
	// to truncate it.
	if len+padLen > int(edns0q.UDPSize()) {
		padLen = int(edns0q.UDPSize()) - len
		if padLen < 0 { // Still doesn't fit? Give up on padding
			padLen = 0
		}
	}
	paddingOpt.Padding = respPadBuf[0:padLen]
}

// Adds padding to a query that is to be sent over DoH or DoT. Padding length is according to rfc8467.
// This should not be used for plain (unencrypted) DNS.
func padQuery(q *dns.Msg) {
	edns0q := q.IsEdns0()
	if edns0q == nil { // Don't pad if the client does not support EDNS0
		return
	}

	// If the query has padding, grab that and truncate it before re-calculating the length
	var paddingOpt *dns.EDNS0_PADDING
	for _, opt := range edns0q.Option {
		if opt.Option() == dns.EDNS0PADDING {
			paddingOpt = opt.(*dns.EDNS0_PADDING)
			paddingOpt.Padding = nil
		}
	}

	// Add the padding option if there isn't one already
	if paddingOpt == nil {
		paddingOpt = new(dns.EDNS0_PADDING)
		edns0q.Option = append(edns0q.Option, paddingOpt)
	}

	// Calculate the desired padding length
	len := q.Len()
	padLen := QueryPaddingBlockSize - len%QueryPaddingBlockSize
	paddingOpt.Padding = queryPadBuf[0:padLen]
}

// Remove padding from a query or response. Typically needed when sending a response that was received
// via TLS over a plain connection.
func stripPadding(m *dns.Msg) {
	edns0 := m.IsEdns0()
	if edns0 == nil { // Nothing to do here
		return
	}
	var newOpt []dns.EDNS0
	for _, opt := range edns0.Option {
		if opt.Option() != dns.EDNS0PADDING {
			newOpt = append(newOpt, opt)
		}
	}
	edns0.Option = newOpt
}

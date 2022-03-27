package rdns

import "testing"

func TestBlocklistloaderManagerSortTLDList(t *testing.T) {
	domains := []string{
		"google.com",
		"www.google.com",
		"yahoo.com",
		"blog.google",
		"dns.google",
		"dns64.dns.google",
		"www.medi-cal.ca.gov",
		"ato.gov.au",
		"a.very.complex-domain.co.uk:",
		"a.domain.that.is.unmanaged",
	}
	var tlds []string = GetTLDsFromDomains(domains)
	SortTLDList(domains, tlds)
}

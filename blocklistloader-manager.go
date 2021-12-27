package rdns

import (
	tld "github.com/jpillora/go-tld"
	"github.com/miekg/dns"
	"net"
)

type TLDDomainBlockListItem struct {
	tld    string
	domain []string
}

func (T TLDDomainBlockListItem) Reload() (BlocklistDB, error) {
	//TODO implement me
}

func (T TLDDomainBlockListItem) Match(q dns.Question) (net.IP, string, string, bool) {
	//TODO implement me
	var listTLDString string = T.tld
	var domainTLDString string = GetTLDFromDomain(q.Name)
	var matchResult bool = listTLDString == domainTLDString
	if matchResult {

	} else {
		return nil, "", "", false // exact match
	}
}

func (T TLDDomainBlockListItem) String() string {
	//TODO implement me
	panic("implement me")
}

var _ BlocklistDB = &TLDDomainBlockListItem{}

func GetTLDListFromFile(fileName FileLoader) {
	//TODO GetTLDsFromDomains in here from file list
}
func GetTLDsFromDomains(domains []string) []string {
	var tlds []string
	for _, domain := range domains {
		var tld = GetTLDFromDomain(domain)
		tlds = append(tlds, tld)
	}
	return tlds
}
func GetTLDFromDomain(domain string) string {
	u, _ := tld.Parse(domain)
	return u.TLD
}
func NewTLDDomainBlockListItem(tld string, domains []string) TLDDomainBlockListItem {
	return TLDDomainBlockListItem{
		tld:     tld,
		domains: domains,
	}
}
func SortTLDList(domains, tlds []string) []TLDDomainBlockListItem {
	var tldDomainBlockList []TLDDomainBlockListItem
	for _, tld := range tlds {
		var newTLDDomainBlockListItem = NewTLDDomainBlockListItem(tld, nil)
		for _, domain := range domains {
			var domainTLD string = GetTLDFromDomain(domain)
			if domainTLD == tld {
				var domainsList []string = newTLDDomainBlockListItem.domains
				domainsList = append(domainsList, domain)
				newTLDDomainBlockListItem = NewTLDDomainBlockListItem(tld, domainsList)
			}
			if domains[len(domains)-1] == domain {
				tldDomainBlockList = append(tldDomainBlockList, newTLDDomainBlockListItem)
			}

		}
	}
}

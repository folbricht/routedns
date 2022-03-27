package rdns

import (
	tld "github.com/jpillora/go-tld"
	"github.com/miekg/dns"
	"net"
	"strings"
)

type TLDDomainBlockListItem struct {
	tld     string
	domains node
}

func (T *TLDDomainBlockListItem) Reload() (BlocklistDB, error) {
	//TODO implement me
}

func (T *TLDDomainBlockListItem) Match(q dns.Question) (net.IP, string, string, bool) {
	//TODO implement me
	var listTLDString string = T.tld
	var domainTLDString string = GetTLDFromDomain(q.Name)
	var matchResult bool = listTLDString == domainTLDString
	if matchResult {
		s := strings.TrimSuffix(q.Name, ".")
		var matched []string
		parts := strings.Split(s, ".")
		n := T.domains
		for i := len(parts) - 1; i >= 0; i-- {
			part := parts[i]
			subNode, ok := n[part]
			if !ok {
				return nil, "", "", false
			}
			matched = append(matched, part)
			if _, ok := subNode[""]; ok { // exact and sub-domain match
				return nil, "", matchedDomainParts(".", matched), true
			}
			if _, ok := subNode["*"]; ok && i > 0 { // wildcard match on sub-domains
				return nil, "", matchedDomainParts("*.", matched), true
			}
			n = subNode
		}
		return nil, "", matchedDomainParts("", matched), len(n) == 0 // exact match
	} else {
		return nil, "", "", false // exact match
	}
}

func (T *TLDDomainBlockListItem) String() string {
	//TODO implement me
	return "Domain"
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
func NewTLDDomainBlockListItem(tld string, domains node) *TLDDomainBlockListItem {
	return &TLDDomainBlockListItem{
		tld:     tld,
		domains: domains,
	}
}

func SortTLDList(domains, tlds []string) []*TLDDomainBlockListItem {
	var tldDomainBlockList []TLDDomainBlockListItem
	for _, tld := range tlds {
		var newTLDDomainBlockListItem = NewTLDDomainBlockListItem(tld, nil)
		for _, domain := range domains {
			var domainTLD string = GetTLDFromDomain(domain)
			if domainTLD == tld {
				var domainsList node = newTLDDomainBlockListItem.domains
				domainsList = add(domainsList)
				newTLDDomainBlockListItem = NewTLDDomainBlockListItem(tld, domainsList)
			}
			if domains[len(domains)-1] == domain {
				tldDomainBlockList = append(tldDomainBlockList, *newTLDDomainBlockListItem)
			}

		}
	}
}

/*
rules, err := loader.Load()
	if err != nil {
		return nil, err
	}
	root := make(node)
	for _, r := range rules {
		r = strings.TrimSpace(r)

		// Strip trailing . in case the list has FQDN names with . suffixes.
		r = strings.TrimSuffix(r, ".")

		// Break up the domain into its parts and iterare backwards over them, building
		// a graph of maps
		parts := strings.Split(r, ".")
		n := root
		for i := len(parts) - 1; i >= 0; i-- {
			part := parts[i]

			// Only allow wildcards as the first domain part, and not in a string
			if strings.Contains(part, "*") && (i > 0 || len(part) != 1) {
				return nil, fmt.Errorf("invalid blocklist item: '%s'", part)
			}

			subNode, ok := n[part]
			if !ok {
				subNode = make(node)
				n[part] = subNode
			}
			n = subNode
		}
	}
	return &DomainDB{root, loader}, nil
*/
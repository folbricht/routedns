package rdns

import (
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"time"
)

// IANARootAnchorsURL is the URL for the IANA root trust anchors XML.
const IANARootAnchorsURL = "https://data.iana.org/root-anchors/root-anchors.xml"

// XML types for unmarshalling the IANA root-anchors.xml format.
type ianaTrustAnchor struct {
	XMLName    xml.Name         `xml:"TrustAnchor"`
	KeyDigests []ianaKeyDigest  `xml:"KeyDigest"`
}

type ianaKeyDigest struct {
	ValidFrom  string `xml:"validFrom,attr"`
	ValidUntil string `xml:"validUntil,attr"`
	KeyTag     uint16 `xml:"KeyTag"`
	Algorithm  uint8  `xml:"Algorithm"`
	DigestType uint8  `xml:"DigestType"`
	Digest     string `xml:"Digest"`
}

// FetchTrustAnchorsFromURL fetches and parses IANA-format trust anchor XML
// from the given URL. Entries past their validUntil date are filtered out.
func FetchTrustAnchorsFromURL(url string) ([]TrustAnchor, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, fmt.Errorf("got unexpected status code %d from %s", resp.StatusCode, url)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response body: %w", err)
	}

	var ta ianaTrustAnchor
	if err := xml.Unmarshal(body, &ta); err != nil {
		return nil, fmt.Errorf("parsing trust anchor XML: %w", err)
	}

	now := time.Now()
	var anchors []TrustAnchor
	for _, kd := range ta.KeyDigests {
		if !isIANAAnchorValid(kd, now) {
			continue
		}
		anchors = append(anchors, TrustAnchor{
			Owner:      ".",
			KeyTag:     kd.KeyTag,
			Algorithm:  kd.Algorithm,
			DigestType: kd.DigestType,
			Digest:     kd.Digest,
		})
	}

	if len(anchors) == 0 {
		return nil, fmt.Errorf("no valid trust anchors found in %s", url)
	}

	return anchors, nil
}

// isIANAAnchorValid checks whether a KeyDigest entry is still valid based
// on its validUntil attribute. Entries without validUntil are always valid.
func isIANAAnchorValid(kd ianaKeyDigest, now time.Time) bool {
	if kd.ValidUntil == "" {
		return true
	}
	t, err := time.Parse(time.RFC3339, kd.ValidUntil)
	if err != nil {
		// If we can't parse the date, treat it as valid to be safe
		return true
	}
	return now.Before(t)
}

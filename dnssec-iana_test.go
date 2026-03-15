package rdns

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestFetchTrustAnchorsXML(t *testing.T) {
	xml := `<?xml version="1.0" encoding="UTF-8"?>
<TrustAnchor>
  <KeyDigest validFrom="2017-02-02T00:00:00+00:00">
    <KeyTag>20326</KeyTag>
    <Algorithm>8</Algorithm>
    <DigestType>2</DigestType>
    <Digest>E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D</Digest>
  </KeyDigest>
  <KeyDigest validFrom="2024-07-18T00:00:00+00:00" validUntil="2099-01-01T00:00:00+00:00">
    <KeyTag>38696</KeyTag>
    <Algorithm>8</Algorithm>
    <DigestType>2</DigestType>
    <Digest>683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16</Digest>
  </KeyDigest>
  <KeyDigest validFrom="2010-07-15T00:00:00+00:00" validUntil="2019-01-11T00:00:00+00:00">
    <KeyTag>19036</KeyTag>
    <Algorithm>8</Algorithm>
    <DigestType>2</DigestType>
    <Digest>49AAC11D7B6F6446702E54A1607371607A1A41855200FD2CE1CDDE32F24E8FB5</Digest>
  </KeyDigest>
</TrustAnchor>`

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		w.Write([]byte(xml))
	}))
	defer srv.Close()

	anchors, err := FetchTrustAnchorsFromURL(srv.URL)
	if err != nil {
		t.Fatal(err)
	}

	// Should have 2 anchors: KSK-2017 (no validUntil) and KSK-2024 (validUntil in 2099).
	// KSK-2010 should be filtered out (validUntil 2019).
	if len(anchors) != 2 {
		t.Fatalf("expected 2 anchors, got %d", len(anchors))
	}

	if anchors[0].KeyTag != 20326 {
		t.Errorf("expected first anchor key-tag 20326, got %d", anchors[0].KeyTag)
	}
	if anchors[0].Owner != "." {
		t.Errorf("expected owner '.', got %q", anchors[0].Owner)
	}
	if anchors[1].KeyTag != 38696 {
		t.Errorf("expected second anchor key-tag 38696, got %d", anchors[1].KeyTag)
	}
	if anchors[1].Algorithm != 8 {
		t.Errorf("expected algorithm 8, got %d", anchors[1].Algorithm)
	}
	if anchors[1].DigestType != 2 {
		t.Errorf("expected digest-type 2, got %d", anchors[1].DigestType)
	}
}

func TestIsIANAAnchorValid(t *testing.T) {
	now := time.Date(2026, 3, 15, 0, 0, 0, 0, time.UTC)

	tests := []struct {
		name       string
		validUntil string
		want       bool
	}{
		{"empty validUntil", "", true},
		{"future date", "2099-01-01T00:00:00+00:00", true},
		{"past date", "2019-01-11T00:00:00+00:00", false},
		{"unparseable date", "not-a-date", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			kd := ianaKeyDigest{ValidUntil: tt.validUntil}
			if got := isIANAAnchorValid(kd, now); got != tt.want {
				t.Errorf("isIANAAnchorValid() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFetchTrustAnchorsHTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	_, err := FetchTrustAnchorsFromURL(srv.URL)
	if err == nil {
		t.Fatal("expected error for HTTP 500, got nil")
	}
}

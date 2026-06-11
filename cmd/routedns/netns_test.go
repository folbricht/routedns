package main

import "testing"

func TestBuildNetNS(t *testing.T) {
	t.Run("neither", func(t *testing.T) {
		ns, err := buildNetNS("", "")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if ns != nil {
			t.Fatalf("expected nil, got %+v", ns)
		}
	})

	t.Run("netns only", func(t *testing.T) {
		ns, err := buildNetNS("container", "")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if ns == nil || ns.Name != "container" || ns.XSocket != "" {
			t.Fatalf("unexpected result: %+v", ns)
		}
	})

	t.Run("xsocket only", func(t *testing.T) {
		ns, err := buildNetNS("", "/run/xsocket/ns1")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if ns == nil || ns.XSocket != "/run/xsocket/ns1" || ns.Name != "" {
			t.Fatalf("unexpected result: %+v", ns)
		}
	})

	t.Run("both is an error", func(t *testing.T) {
		if _, err := buildNetNS("container", "/run/xsocket/ns1"); err == nil {
			t.Fatal("expected an error when both netns and xsocket are set")
		}
	})
}

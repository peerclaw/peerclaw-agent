package agent

import (
	"testing"
)

func TestNew_GeneratesKeypair(t *testing.T) {
	a, err := New(Options{
		Name:      "TestAgent",
		ServerURL: "http://localhost:8080",
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if a.PublicKey() == "" {
		t.Error("expected non-empty public key")
	}
}

func TestNew_WithKeypairPath(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/keypair.seed"

	a1, err := New(Options{
		Name:        "TestAgent",
		ServerURL:   "http://localhost:8080",
		KeypairPath: path,
	})
	if err != nil {
		t.Fatalf("New (create): %v", err)
	}
	pk1 := a1.PublicKey()

	a2, err := New(Options{
		Name:        "TestAgent",
		ServerURL:   "http://localhost:8080",
		KeypairPath: path,
	})
	if err != nil {
		t.Fatalf("New (load): %v", err)
	}
	pk2 := a2.PublicKey()

	if pk1 != pk2 {
		t.Error("loaded keypair should produce same public key")
	}
}

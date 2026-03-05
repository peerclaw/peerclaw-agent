package identity

import (
	"fmt"
	"net"
	"strings"
)

// DomainVerifier verifies DNS TXT record domain bindings.
type DomainVerifier struct{}

// NewDomainVerifier creates a new domain verifier.
func NewDomainVerifier() *DomainVerifier {
	return &DomainVerifier{}
}

// Verify checks if a DNS TXT record exists binding the domain to the given fingerprint.
// It looks for a TXT record in the format: peerclaw-verify=<fingerprint>
func (dv *DomainVerifier) Verify(domain, fingerprint string) (bool, error) {
	if domain == "" || fingerprint == "" {
		return false, fmt.Errorf("domain and fingerprint are required")
	}

	records, err := net.LookupTXT(domain)
	if err != nil {
		return false, fmt.Errorf("DNS TXT lookup for %s: %w", domain, err)
	}

	expected := "peerclaw-verify=" + fingerprint
	for _, record := range records {
		if strings.TrimSpace(record) == expected {
			return true, nil
		}
	}

	return false, nil
}

// ExpectedTXTRecord returns the TXT record value that should be set for domain verification.
func ExpectedTXTRecord(fingerprint string) string {
	return "peerclaw-verify=" + fingerprint
}

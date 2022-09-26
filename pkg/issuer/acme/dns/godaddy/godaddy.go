// +skip_license_check

/*
This file contains portions of code directly taken from the 'go-acme/lego' project.
A copy of the license for this code can be found in the file named LICENSE in
this directory.
*/

// Package godaddy implements a DNS provider for solving the DNS-01
// challenge using GoDaddy DNS.
package godaddy

import (
	"fmt"
	"os"
	"strings"

	"github.com/cert-manager/cert-manager/pkg/issuer/acme/dns/util"
)

// DNSProvider is an implementation of the acme.ChallengeProvider interface.
type DNSProvider struct {
	dns01Nameservers []string
	client           *Client
}

// NewDNSProvider returns a DNSProvider instance configured for godaddy.
// Credentials must be passed in the environment variables: GODADDY_API_KEY
// and GODADDY_API_SECRET.
func NewDNSProvider(dns01Nameservers []string) (*DNSProvider, error) {
	key := os.Getenv("GODADDY_API_KEY")
	secret := os.Getenv("GODADDY_API_SECRET")
	return NewDNSProviderCredentials(key, secret, dns01Nameservers)
}

// NewDNSProviderCredentials uses the supplied credentials to return a
// DNSProvider instance configured for godaddy.
func NewDNSProviderCredentials(key, secret string, dns01Nameservers []string) (*DNSProvider, error) {
	if key == "" || secret == "" {
		return nil, fmt.Errorf("godaddy: missing credentials")
	}
	return &DNSProvider{
		dns01Nameservers: dns01Nameservers,
		client:           NewClient(key, secret),
	}, nil
}

// Present creates a TXT record to fulfil the dns-01 challenge.
func (p *DNSProvider) Present(domain, fqdn, value string) error {
	authZone, err := util.FindZoneByFqdn(fqdn, p.dns01Nameservers)
	if err != nil {
		return err
	}

	zoneName := util.UnFqdn(authZone)
	recordName := extractRecordName(fqdn, zoneName)

	// check if the record has already been created.
	record, err := p.client.GetTXTRecord(zoneName, recordName)
	if err != nil {
		return err
	}

	// create if it doesn't exist already...
	if record == nil {
		return p.client.SetTXTRecord(zoneName, recordName, &DNSRecord{
			Name: recordName,
			Type: "TXT",
			Data: value,
		})
	}

	// ... or update when it's out of date.
	if record.Data != value {
		record.Data = value
		return p.client.SetTXTRecord(zoneName, recordName, record)
	}

	return nil
}

// CleanUp removes the TXT record matching the specified parameters.
func (p *DNSProvider) CleanUp(domain, fqdn, value string) error {
	authZone, err := util.FindZoneByFqdn(fqdn, p.dns01Nameservers)
	if err != nil {
		return err
	}

	zoneName := util.UnFqdn(authZone)
	recordName := extractRecordName(fqdn, zoneName)

	return p.client.DeleteTXTRecord(zoneName, recordName)
}

func extractRecordName(fqdn, zone string) string {
	name := util.UnFqdn(fqdn)
	if idx := strings.Index(name, "."+zone); idx != -1 {
		return name[:idx]
	}
	return name
}

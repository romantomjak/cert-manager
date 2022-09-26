// +skip_license_check

/*
This file contains portions of code directly taken from the 'go-acme/lego' project.
A copy of the license for this code can be found in the file named LICENSE in
this directory.
*/

package godaddy

import (
	"os"
	"testing"
	"time"

	"github.com/cert-manager/cert-manager/pkg/issuer/acme/dns/util"
	"github.com/stretchr/testify/assert"
)

var (
	gdLiveTest  bool
	gdAPIKey    string
	gdAPISecret string
	gdDomain    string
)

func init() {
	gdAPIKey = os.Getenv("GODADDY_API_KEY")
	gdAPISecret = os.Getenv("GODADDY_API_SECRET")
	gdDomain = os.Getenv("GODADDY_DOMAIN")
	if len(gdAPIKey) > 0 && len(gdAPISecret) > 0 && len(gdDomain) > 0 {
		gdLiveTest = true
	}
}

func restoreGoDaddyEnv() {
	os.Setenv("GODADDY_API_KEY", gdAPIKey)
	os.Setenv("GODADDY_API_SECRET", gdAPISecret)
	os.Setenv("GODADDY_DOMAIN", gdDomain)
}

func TestNewDNSProviderValid(t *testing.T) {
	os.Setenv("GODADDY_API_KEY", "")
	os.Setenv("GODADDY_API_SECRET", "")
	_, err := NewDNSProviderCredentials("123", "123", util.RecursiveNameservers)
	assert.NoError(t, err)
	restoreGoDaddyEnv()
}

func TestNewDNSProviderValidEnv(t *testing.T) {
	os.Setenv("GODADDY_API_KEY", "123")
	os.Setenv("GODADDY_API_SECRET", "123")
	_, err := NewDNSProvider(util.RecursiveNameservers)
	assert.NoError(t, err)
	restoreGoDaddyEnv()
}

func TestNewDNSProviderMissingCredErr(t *testing.T) {
	os.Setenv("GODADDY_API_SECRET", "")
	_, err := NewDNSProvider(util.RecursiveNameservers)
	assert.EqualError(t, err, "godaddy: missing credentials")
	restoreGoDaddyEnv()
}

func TestGoDaddyPresent(t *testing.T) {
	if !gdLiveTest {
		t.Skip("skipping live test")
	}

	provider, err := NewDNSProviderCredentials(gdAPIKey, gdAPISecret, util.RecursiveNameservers)
	assert.NoError(t, err)

	err = provider.Present(gdDomain, "_acme-challenge."+gdDomain+".", "123d==")
	assert.NoError(t, err)
}

func TestGoDaddyCleanUp(t *testing.T) {
	if !gdLiveTest {
		t.Skip("skipping live test")
	}

	time.Sleep(time.Second * 2)

	provider, err := NewDNSProviderCredentials(gdAPIKey, gdAPISecret, util.RecursiveNameservers)
	assert.NoError(t, err)

	err = provider.CleanUp(gdDomain, "_acme-challenge."+gdDomain+".", "123d==")
	assert.NoError(t, err)
}

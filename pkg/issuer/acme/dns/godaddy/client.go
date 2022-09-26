// +skip_license_check

/*
This file contains portions of code directly taken from the 'go-acme/lego' project.
A copy of the license for this code can be found in the file named LICENSE in
this directory.
*/

package godaddy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"time"
)

const baseURL = "https://api.godaddy.com"

type Client struct {
	baseURL    *url.URL
	apiKey     string
	apiSecret  string
	httpClient *http.Client
}

type APIError struct {
	Code    string `json:"code,omitempty"`
	Message string `json:"message,omitempty"`
}

type DNSRecord struct {
	Name     string `json:"name,omitempty"`
	Type     string `json:"type,omitempty"`
	Data     string `json:"data"`
	TTL      int    `json:"ttl,omitempty"`
	Priority int    `json:"priority,omitempty"`
	Port     int    `json:"port,omitempty"`
	Protocol string `json:"protocol,omitempty"`
	Service  string `json:"service,omitempty"`
	Weight   int    `json:"weight,omitempty"`
}

func NewClient(apiKey string, apiSecret string) *Client {
	baseURL, _ := url.Parse(baseURL)

	return &Client{
		baseURL:    baseURL,
		apiKey:     apiKey,
		apiSecret:  apiSecret,
		httpClient: &http.Client{Timeout: 30 * time.Second},
	}
}

func (c *Client) GetTXTRecord(domain, recordName string) (*DNSRecord, error) {
	if recordName == "" {
		return nil, fmt.Errorf("record name cannot be empty")
	}

	url := fmt.Sprintf("/v1/domains/%s/records/TXT/%s", domain, recordName)
	resp, err := c.newRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to get record %s for domain %s: %v", recordName, domain, err)
		}
		return nil, fmt.Errorf("failed to get record %s for domain %s: %s", recordName, domain, parseAPIError(bodyBytes))
	}

	var records []DNSRecord
	if err := json.NewDecoder(resp.Body).Decode(&records); err != nil {
		return nil, err
	}

	for _, r := range records {
		if r.Name == recordName {
			return &r, nil
		}
	}

	return nil, nil
}

func (c *Client) SetTXTRecord(domain, recordName string, record *DNSRecord) error {
	body, err := json.Marshal([]DNSRecord{*record})
	if err != nil {
		return err
	}

	url := fmt.Sprintf("/v1/domains/%s/records/TXT/%s", domain, recordName)
	resp, err := c.newRequest(http.MethodPut, url, bytes.NewReader(body))
	if err != nil {
		return err
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("failed to create record %s for domain %s: %v", recordName, domain, err)
		}
		return fmt.Errorf("failed to create record %s for domain %s: %s", recordName, domain, parseAPIError(bodyBytes))
	}

	return nil
}

func (c *Client) DeleteTXTRecord(domain, recordName string) error {
	url := fmt.Sprintf("/v1/domains/%s/records/TXT/%s", domain, recordName)
	resp, err := c.newRequest(http.MethodDelete, url, nil)
	if err != nil {
		return err
	}

	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusNoContent, http.StatusNotFound:
		return nil
	default:
		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("failed to delete record %s for domain %s: %v", recordName, domain, err)
		}
		return fmt.Errorf("failed to delete record %s for domain %s: %s", recordName, domain, parseAPIError(bodyBytes))
	}
}

func (c *Client) newRequest(method, url string, body io.Reader) (*http.Response, error) {
	reqURL, err := c.baseURL.Parse(path.Join(c.baseURL.Path, url))
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest(method, reqURL.String(), body)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("sso-key %s:%s", c.apiKey, c.apiSecret))

	return c.httpClient.Do(req)
}

func parseAPIError(body []byte) string {
	var apiErr *APIError
	if err := json.Unmarshal(body, apiErr); err != nil {
		return string(body)
	}
	return fmt.Sprintf("%s %s", apiErr.Code, apiErr.Message)
}

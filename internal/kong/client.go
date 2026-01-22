package kong

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"k8s.io/klog/v2"
)

type Client struct {
	adminURL   string
	adminToken string
	httpClient *http.Client
}

type Certificate struct {
	ID        string   `json:"id,omitempty"`
	Cert      string   `json:"cert"`
	Key       string   `json:"key"`
	SNIs      []string `json:"snis,omitempty"`
	Tags      []string `json:"tags,omitempty"`
	CreatedAt int64    `json:"created_at,omitempty"`
	UpdatedAt int64    `json:"updated_at,omitempty"`
}

type CertificateListResponse struct {
	Data []Certificate `json:"data"`
	Next *string       `json:"next,omitempty"`
}

func NewClient(adminURL, adminToken string) *Client {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	return &Client{
		adminURL:   strings.TrimSuffix(adminURL, "/"),
		adminToken: adminToken,
		httpClient: &http.Client{
			Transport: tr,
			Timeout:   30 * time.Second,
		},
	}
}

func (c *Client) CreateOrUpdateCertificate(cert *Certificate) error {
	if len(cert.SNIs) == 0 {
		return fmt.Errorf("certificate must have at least one SNI")
	}

	klog.Infof("Processing certificate with SNIs: %v", cert.SNIs)

	existingCert, err := c.findCertificateByAnySNI(cert.SNIs)
	if err != nil {
		return fmt.Errorf("failed to check existing certificate: %v", err)
	}

	if existingCert != nil {
		if c.certificateNeedsUpdate(existingCert, cert) {
			klog.Infof("Certificate with SNIs %v already exists (ID: %s), updating...",
				cert.SNIs, existingCert.ID)
			return c.updateCertificate(existingCert.ID, cert)
		} else {
			klog.Infof("Certificate with SNIs %v already exists (ID: %s) and is up to date, skipping",
				cert.SNIs, existingCert.ID)
			return nil
		}
	}

	klog.Infof("Creating new certificate for SNIs: %v", cert.SNIs)
	return c.createCertificate(cert)
}

func (c *Client) findCertificateByAnySNI(snis []string) (*Certificate, error) {
	if len(snis) == 0 {
		return nil, nil
	}

	allCerts, err := c.listAllCertificates()
	if err != nil {
		return nil, fmt.Errorf("failed to list certificates: %v", err)
	}

	klog.V(3).Infof("Searching for certificate with SNIs: %v among %d certificates", snis, len(allCerts))

	for _, cert := range allCerts {
		certSNISet := make(map[string]bool)
		for _, certSNI := range cert.SNIs {
			certSNISet[certSNI] = true
		}

		for _, sni := range snis {
			if certSNISet[sni] {
				klog.V(2).Infof("Found existing certificate with matching SNI %s (ID: %s, all SNIs: %v)",
					sni, cert.ID, cert.SNIs)
				return &cert, nil
			}
		}
	}

	klog.V(2).Infof("No existing certificate found with any of SNIs: %v", snis)
	return nil, nil
}

func (c *Client) listAllCertificates() ([]Certificate, error) {
	var allCerts []Certificate
	url := fmt.Sprintf("%s/certificates", c.adminURL)

	var next *string
	next = &url

	for next != nil {
		certs, nextPage, err := c.listCertificatesPage(*next)
		if err != nil {
			return nil, err
		}

		allCerts = append(allCerts, certs...)
		next = nextPage
	}

	klog.V(3).Infof("Found %d certificates in Kong", len(allCerts))
	return allCerts, nil
}

func (c *Client) listCertificatesPage(url string) ([]Certificate, *string, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, nil, err
	}
	c.setHeaders(req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get certificates: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, nil, fmt.Errorf("failed to list certificates: %s - %s", resp.Status, string(bodyBytes))
	}

	var listResp CertificateListResponse
	if err := json.NewDecoder(resp.Body).Decode(&listResp); err != nil {
		return nil, nil, fmt.Errorf("failed to decode certificate list: %v", err)
	}

	return listResp.Data, listResp.Next, nil
}

func (c *Client) createCertificate(cert *Certificate) error {
	url := fmt.Sprintf("%s/certificates", c.adminURL)

	reqBody, err := json.Marshal(cert)
	if err != nil {
		return fmt.Errorf("failed to marshal certificate: %v", err)
	}

	klog.V(2).Infof("Creating certificate with SNIs: %v", cert.SNIs)
	return c.sendRequest(http.MethodPost, url, reqBody)
}

func (c *Client) updateCertificate(certID string, cert *Certificate) error {
	url := fmt.Sprintf("%s/certificates/%s", c.adminURL, certID)

	reqBody, err := json.Marshal(cert)
	if err != nil {
		return fmt.Errorf("failed to marshal certificate: %v", err)
	}

	klog.V(2).Infof("Updating certificate %s with SNIs: %v", certID, cert.SNIs)
	return c.sendRequest(http.MethodPatch, url, reqBody)
}

func (c *Client) certificateNeedsUpdate(existing, newCert *Certificate) bool {
	existingCertClean := strings.TrimSpace(existing.Cert)
	newCertClean := strings.TrimSpace(newCert.Cert)
	existingKeyClean := strings.TrimSpace(existing.Key)
	newKeyClean := strings.TrimSpace(newCert.Key)

	if existingCertClean != newCertClean {
		klog.V(2).Infof("Certificate content changed")
		return true
	}

	if existingKeyClean != newKeyClean {
		klog.V(2).Infof("Private key changed")
		return true
	}

	if len(existing.SNIs) != len(newCert.SNIs) {
		klog.V(2).Infof("SNI count changed from %d to %d", len(existing.SNIs), len(newCert.SNIs))
		return true
	}

	existingSNISet := make(map[string]bool)
	for _, sni := range existing.SNIs {
		existingSNISet[sni] = true
	}

	for _, sni := range newCert.SNIs {
		if !existingSNISet[sni] {
			klog.V(2).Infof("SNI list changed, new SNI: %s", sni)
			return true
		}
	}

	klog.V(2).Infof("Certificate does not need update")
	return false
}

func (c *Client) DeleteCertificateBySNIs(snis []string) error {
	if len(snis) == 0 {
		return nil
	}

	cert, err := c.findCertificateByAnySNI(snis)
	if err != nil {
		return fmt.Errorf("failed to find certificate by SNIs: %v", err)
	}

	if cert == nil {
		klog.Infof("Certificate with SNIs %v does not exist, skipping deletion", snis)
		return nil
	}

	return c.deleteCertificate(cert.ID)
}

func (c *Client) deleteCertificate(certID string) error {
	url := fmt.Sprintf("%s/certificates/%s", c.adminURL, certID)

	req, err := http.NewRequest(http.MethodDelete, url, nil)
	if err != nil {
		return err
	}
	c.setHeaders(req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusNotFound {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to delete certificate: %s - %s", resp.Status, string(bodyBytes))
	}

	klog.Infof("Successfully deleted certificate %s", certID)
	return nil
}

func (c *Client) sendRequest(method, url string, body []byte) error {
	var reqBody io.Reader
	if body != nil {
		reqBody = bytes.NewBuffer(body)
	}

	req, err := http.NewRequest(method, url, reqBody)
	if err != nil {
		return fmt.Errorf("failed to create request: %v", err)
	}
	c.setHeaders(req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request to %s: %v", url, err)
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(resp.Body)

	if method == http.MethodPost && resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("failed to create certificate: %s - %s", resp.Status, string(bodyBytes))
	}

	if method == http.MethodPatch && resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to update certificate: %s - %s", resp.Status, string(bodyBytes))
	}

	if resp.StatusCode >= 400 {
		return fmt.Errorf("Kong API error: %s - %s", resp.Status, string(bodyBytes))
	}

	klog.V(2).Infof("Successfully %s certificate via Kong API", method)
	return nil
}

func (c *Client) setHeaders(req *http.Request) {
	req.Header.Set("Content-Type", "application/json")
	if c.adminToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.adminToken)
	}
}

func (c *Client) ValidateConnection() error {
	_, err := c.listAllCertificates()
	if err != nil {
		return fmt.Errorf("failed to connect to Kong: %v", err)
	}

	klog.Info("Successfully connected to Kong Admin API")
	return nil
}

func (c *Client) GetCertificateCount() (int, error) {
	certs, err := c.listAllCertificates()
	if err != nil {
		return 0, err
	}
	return len(certs), nil
}

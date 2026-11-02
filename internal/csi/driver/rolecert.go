/*
Copyright The Athenz Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package driver

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/cert-manager/csi-lib/metadata"
)

const (
	roleCertFileSuffix = ".cert.pem"
	roleKeyFileSuffix  = ".key.pem"

	ztsRequestTimeout = 30 * time.Second

	// roleCertRetryInterval bounds the next issuance when a role certificate
	// renewal failed and the previous certificate was carried forward.
	roleCertRetryInterval = 10 * time.Minute

	maxZTSResponseBytes = 1 << 20
	maxZTSErrorBodyLen  = 512
)

// Athenz DomainName / EntityName; also keeps role file names free of `..` and `/`.
var athenzNameRegexp = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_-]*(\.[A-Za-z0-9_][A-Za-z0-9_-]*)*$`)

type roleCertRef struct {
	domain, role string
}

func (r roleCertRef) name() string         { return r.domain + ":role." + r.role }
func (r roleCertRef) certFileName() string { return r.name() + roleCertFileSuffix }
func (r roleCertRef) keyFileName() string  { return r.name() + roleKeyFileSuffix }

// parseRoleCerts parses the comma-separated `<domain>:role.<role>` list of the
// role-certs volume attribute.
func parseRoleCerts(attr string) ([]roleCertRef, error) {
	var refs []roleCertRef
	seen := map[string]struct{}{}
	for _, entry := range strings.Split(attr, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		domain, role, ok := strings.Cut(entry, ":role.")
		if !ok || !athenzNameRegexp.MatchString(domain) || !athenzNameRegexp.MatchString(role) {
			return nil, fmt.Errorf("invalid %s entry %q: must be <domain>:role.<role>", attrRoleCerts, entry)
		}
		ref := roleCertRef{domain: domain, role: role}
		if len(ref.certFileName()) > inplaceMaxFileNameLength {
			return nil, fmt.Errorf("invalid %s entry %q: name too long", attrRoleCerts, entry)
		}
		if _, dup := seen[entry]; dup {
			continue
		}
		seen[entry] = struct{}{}
		refs = append(refs, ref)
	}
	return refs, nil
}

type fileReader interface {
	ReadFile(volumeID, name string) ([]byte, error)
}

// issueRoleCerts carries a role forward from the volume when ZTS refuses it, and fails only if there is nothing to carry.
func (d *Driver) issueRoleCerts(meta metadata.Metadata, key crypto.PrivateKey, chain []byte, refs []roleCertRef) (map[string][]byte, *time.Time, error) {
	client, principal, clientErr := d.newZTSClient(key, chain)
	if client != nil {
		defer client.CloseIdleConnections()
	}

	files := make(map[string][]byte, 2*len(refs))
	var next *time.Time
	earlier := func(t time.Time) {
		if next == nil || t.Before(*next) {
			next = &t
		}
	}

	for _, ref := range refs {
		err := clientErr
		if err == nil {
			var certPEM, keyPEM []byte
			var leaf *x509.Certificate
			certPEM, keyPEM, leaf, err = d.fetchRoleCert(client, principal, ref)
			if err == nil {
				files[ref.certFileName()] = certPEM
				files[ref.keyFileName()] = keyPEM
				earlier(leaf.NotBefore.Add(leaf.NotAfter.Sub(leaf.NotBefore) * 2 / 3))
				continue
			}
		}

		prevCert, prevKey, ok := d.readPreviousRoleCert(meta.VolumeID, ref)
		if !ok {
			return nil, nil, fmt.Errorf("issuing role certificate %q: %w", ref.name(), err)
		}
		d.log.Error(err, "failed to renew role certificate, keeping the previous one",
			"volume", meta.VolumeID, "role", ref.name())
		files[ref.certFileName()] = prevCert
		files[ref.keyFileName()] = prevKey
		earlier(time.Now().Add(roleCertRetryInterval))
	}

	return files, next, nil
}

func (d *Driver) readPreviousRoleCert(volumeID string, ref roleCertRef) ([]byte, []byte, bool) {
	reader, ok := d.store.(fileReader)
	if !ok {
		return nil, nil, false
	}
	certPEM, err := reader.ReadFile(volumeID, ref.certFileName())
	if err != nil || len(certPEM) == 0 {
		return nil, nil, false
	}
	keyPEM, err := reader.ReadFile(volumeID, ref.keyFileName())
	if err != nil || len(keyPEM) == 0 {
		return nil, nil, false
	}
	return certPEM, keyPEM, true
}

type ztsClient struct {
	http      *http.Client
	transport *http.Transport
	url       string
}

func (c *ztsClient) CloseIdleConnections() { c.transport.CloseIdleConnections() }

func (d *Driver) newZTSClient(key crypto.PrivateKey, chain []byte) (*ztsClient, string, error) {
	if d.zts == "" {
		return nil, "", fmt.Errorf("role certificates requested but no ZTS URL is configured")
	}
	ztsURL, err := url.Parse(d.zts)
	if err != nil || ztsURL.Scheme != "https" || ztsURL.Host == "" {
		return nil, "", fmt.Errorf("ZTS URL %q must be an absolute https URL", d.zts)
	}

	certs, err := parseCertChain(chain)
	if err != nil {
		return nil, "", fmt.Errorf("parsing service certificate chain: %w", err)
	}
	leaf, _ := pickLeaf(certs)
	if leaf == nil {
		return nil, "", fmt.Errorf("no certificates found in service certificate chain")
	}
	if leaf.Subject.CommonName == "" {
		return nil, "", fmt.Errorf("service certificate has no common name to use as principal")
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, "", fmt.Errorf("service private key of type %T cannot sign", key)
	}

	clientCert := &tls.Certificate{PrivateKey: signer, Leaf: leaf}
	clientCert.Certificate = append(clientCert.Certificate, leaf.Raw)
	for _, c := range certs {
		if c != leaf {
			clientCert.Certificate = append(clientCert.Certificate, c.Raw)
		}
	}

	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		// Always present the service certificate, even if its issuer is not in
		// the server's acceptable CA list.
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			return clientCert, nil
		},
	}
	if d.caCertFile != "" {
		caPEM, err := os.ReadFile(d.caCertFile)
		if err != nil {
			return nil, "", fmt.Errorf("reading ZTS CA bundle: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			return nil, "", fmt.Errorf("no certificates found in ZTS CA bundle %q", d.caCertFile)
		}
		tlsConfig.RootCAs = pool
	}

	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = tlsConfig

	return &ztsClient{
		http:      &http.Client{Transport: transport, Timeout: ztsRequestTimeout},
		transport: transport,
		url:       strings.TrimSuffix(d.zts, "/") + "/rolecert",
	}, leaf.Subject.CommonName, nil
}

type ztsRoleCertificateRequest struct {
	CSR string `json:"csr"`
	// Zero lets ZTS apply the role's configured or default lifetime.
	ExpiryTime int64 `json:"expiryTime"`
}

type ztsRoleCertificate struct {
	X509Certificate string `json:"x509Certificate"`
}

func (d *Driver) fetchRoleCert(client *ztsClient, principal string, ref roleCertRef) ([]byte, []byte, *x509.Certificate, error) {
	roleKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("generating role private key: %w", err)
	}

	csrPEM, err := d.roleCertCSR(roleKey, principal, ref)
	if err != nil {
		return nil, nil, nil, err
	}

	body, err := json.Marshal(ztsRoleCertificateRequest{CSR: string(csrPEM)})
	if err != nil {
		return nil, nil, nil, fmt.Errorf("encoding role certificate request: %w", err)
	}
	req, err := http.NewRequest(http.MethodPost, client.url, bytes.NewReader(body))
	if err != nil {
		return nil, nil, nil, fmt.Errorf("building role certificate request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := client.http.Do(req)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("requesting role certificate from ZTS: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxZTSResponseBytes))
	if err != nil {
		return nil, nil, nil, fmt.Errorf("reading ZTS response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		msg := strings.TrimSpace(string(respBody))
		if len(msg) > maxZTSErrorBodyLen {
			msg = msg[:maxZTSErrorBodyLen] + "..."
		}
		return nil, nil, nil, fmt.Errorf("ZTS returned %s: %s", resp.Status, msg)
	}

	certPEM, err := roleCertFromResponse(respBody)
	if err != nil {
		return nil, nil, nil, err
	}
	certs, err := parseCertChain(certPEM)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("parsing role certificate from ZTS: %w", err)
	}
	leaf, _ := pickLeaf(certs)
	if leaf == nil {
		return nil, nil, nil, fmt.Errorf("no certificate in ZTS role certificate response")
	}
	if !roleKey.PublicKey.Equal(leaf.PublicKey) {
		return nil, nil, nil, fmt.Errorf("role certificate from ZTS does not match the requested key")
	}

	keyDER, err := x509.MarshalPKCS8PrivateKey(roleKey)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("marshalling role private key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	return certPEM, keyPEM, leaf, nil
}

func (d *Driver) roleCertCSR(key *ecdsa.PrivateKey, principal string, ref roleCertRef) ([]byte, error) {
	subj := pkix.Name{CommonName: ref.name()}
	if d.certCountryName != "" {
		subj.Country = []string{d.certCountryName}
	}
	if d.certOrgName != "" {
		subj.Organization = []string{d.certOrgName}
	}

	spiffeURI, err := url.Parse(fmt.Sprintf("spiffe://%s/ra/%s", ref.domain, ref.role))
	if err != nil {
		return nil, fmt.Errorf("building role spiffe URI: %w", err)
	}
	principalURI, err := url.Parse("athenz://principal/" + principal)
	if err != nil {
		return nil, fmt.Errorf("building principal URI: %w", err)
	}

	csrPEM, err := signRequest(metadata.Metadata{}, key, &x509.CertificateRequest{
		Subject:            subj,
		URIs:               []*url.URL{spiffeURI, principalURI},
		SignatureAlgorithm: x509.ECDSAWithSHA256,
	})
	if err != nil {
		return nil, fmt.Errorf("signing role certificate request: %w", err)
	}
	return csrPEM, nil
}

// roleCertFromResponse accepts a ZTS RoleCertificate JSON body or a bare PEM.
func roleCertFromResponse(body []byte) ([]byte, error) {
	var rc ztsRoleCertificate
	if err := json.Unmarshal(body, &rc); err == nil && rc.X509Certificate != "" {
		return []byte(rc.X509Certificate), nil
	}
	if trimmed := bytes.TrimSpace(body); bytes.HasPrefix(trimmed, []byte("-----BEGIN ")) {
		return append(trimmed, '\n'), nil
	}
	return nil, fmt.Errorf("unrecognised ZTS role certificate response")
}

func roleCertFiles(volumeContext map[string]string) ([]string, error) {
	refs, err := parseRoleCerts(volumeContext[attrRoleCerts])
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, 2*len(refs))
	for _, ref := range refs {
		names = append(names, ref.certFileName(), ref.keyFileName())
	}
	return names, nil
}

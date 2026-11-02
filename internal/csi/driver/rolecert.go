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
	roleP12FileSuffix  = ".pkcs12"
	roleJKSFileSuffix  = ".jks"

	// roleJKSAlias matches the alias keytool assigns when SIA imports its openssl PKCS12.
	roleJKSAlias = "1"

	ztsRequestTimeout = 30 * time.Second

	// roleCertRetryInterval bounds the next issuance when a role certificate
	// renewal failed and the previous certificate was carried forward.
	roleCertRetryInterval = 10 * time.Minute

	maxZTSResponseBytes = 1 << 20
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
		var certPEM, keyPEM []byte
		err := clientErr
		if err == nil {
			var rc *roleCert
			if rc, err = d.fetchRoleCert(client, principal, ref); err == nil {
				certPEM, keyPEM = rc.cert, rc.key
				earlier(rc.renewAt)
			}
		}

		if err != nil {
			var ok bool
			if certPEM, keyPEM, ok = d.readPreviousRoleCert(meta.VolumeID, ref); !ok {
				return nil, nil, fmt.Errorf("issuing role certificate %q: %w", ref.name(), err)
			}
			d.log.Error(err, "failed to renew role certificate, keeping the previous one",
				"volume", meta.VolumeID, "role", ref.name())
			earlier(time.Now().Add(roleCertRetryInterval))
		}

		files[ref.certFileName()] = certPEM
		files[ref.keyFileName()] = keyPEM
		if err := d.addRoleKeystores(files, ref, certPEM, keyPEM); err != nil {
			return nil, nil, err
		}
	}

	return files, next, nil
}

// addRoleKeystores writes `<role>.pkcs12` and `<role>.jks` under the same switches as the service keystores.
func (d *Driver) addRoleKeystores(files map[string][]byte, ref roleCertRef, certPEM, keyPEM []byte) error {
	if !d.keystoreEnabled || (d.keystoreFileName == "" && d.jksFileName == "") {
		return nil
	}

	certs, err := parseCertChain(certPEM)
	if err != nil {
		return fmt.Errorf("parsing role certificate %q for keystore: %w", ref.name(), err)
	}
	leaf, _ := pickLeaf(certs)
	if leaf == nil {
		return fmt.Errorf("no certificate in role certificate %q for keystore", ref.name())
	}
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return fmt.Errorf("decoding role private key %q for keystore", ref.name())
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("parsing role private key %q for keystore: %w", ref.name(), err)
	}

	if d.keystoreFileName != "" {
		p12, err := encodePKCS12(key, leaf, d.keystorePassword)
		if err != nil {
			return fmt.Errorf("encoding PKCS12 keystore for role %q: %w", ref.name(), err)
		}
		files[ref.name()+roleP12FileSuffix] = p12
	}
	if d.jksFileName != "" {
		jks, err := encodeJKS(block.Bytes, leaf, roleJKSAlias, d.keystorePassword)
		if err != nil {
			return fmt.Errorf("encoding JKS keystore for role %q: %w", ref.name(), err)
		}
		files[ref.name()+roleJKSFileSuffix] = jks
	}
	return nil
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

func (d *Driver) newZTSClient(key crypto.PrivateKey, chain []byte) (*http.Client, string, error) {
	if d.zts == "" {
		return nil, "", fmt.Errorf("role certificates requested but no ZTS URL is configured")
	}

	certs, err := parseCertChain(chain)
	if err != nil {
		return nil, "", fmt.Errorf("parsing service certificate chain: %w", err)
	}
	leaf, _ := pickLeaf(certs)
	if leaf == nil {
		return nil, "", fmt.Errorf("no certificates found in service certificate chain")
	}

	clientCert := &tls.Certificate{PrivateKey: key, Leaf: leaf}
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

	return &http.Client{Transport: transport, Timeout: ztsRequestTimeout}, leaf.Subject.CommonName, nil
}

type ztsRoleCertificateRequest struct {
	CSR string `json:"csr"`
	// Zero lets ZTS apply the role's configured or default lifetime.
	ExpiryTime int64 `json:"expiryTime"`
}

type ztsRoleCertificate struct {
	X509Certificate string `json:"x509Certificate"`
}

type roleCert struct {
	cert, key []byte
	renewAt   time.Time
}

func (d *Driver) fetchRoleCert(client *http.Client, principal string, ref roleCertRef) (*roleCert, error) {
	roleKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating role private key: %w", err)
	}

	csrPEM, err := d.roleCertCSR(roleKey, principal, ref)
	if err != nil {
		return nil, err
	}

	body, err := json.Marshal(ztsRoleCertificateRequest{CSR: string(csrPEM)})
	if err != nil {
		return nil, fmt.Errorf("encoding role certificate request: %w", err)
	}
	req, err := http.NewRequest(http.MethodPost, strings.TrimSuffix(d.zts, "/")+"/rolecert", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("building role certificate request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("requesting role certificate from ZTS: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxZTSResponseBytes))
	if err != nil {
		return nil, fmt.Errorf("reading ZTS response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("ZTS returned %s: %s", resp.Status, strings.TrimSpace(string(respBody)))
	}

	var rc ztsRoleCertificate
	if err := json.Unmarshal(respBody, &rc); err != nil {
		return nil, fmt.Errorf("decoding ZTS role certificate response: %w", err)
	}
	certPEM := []byte(rc.X509Certificate)
	certs, err := parseCertChain(certPEM)
	if err != nil {
		return nil, fmt.Errorf("parsing role certificate from ZTS: %w", err)
	}
	leaf, _ := pickLeaf(certs)
	if leaf == nil {
		return nil, fmt.Errorf("no certificate in ZTS role certificate response")
	}

	keyDER, err := x509.MarshalPKCS8PrivateKey(roleKey)
	if err != nil {
		return nil, fmt.Errorf("marshalling role private key: %w", err)
	}

	return &roleCert{
		cert:    certPEM,
		key:     pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
		renewAt: leaf.NotBefore.Add(leaf.NotAfter.Sub(leaf.NotBefore) * 2 / 3),
	}, nil
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

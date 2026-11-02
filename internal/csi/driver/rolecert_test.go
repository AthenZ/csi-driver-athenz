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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cert-manager/csi-lib/metadata"
	"github.com/cert-manager/csi-lib/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/klog/v2/klogr"
)

const (
	testPrincipal = "k8s.omega.aws-nonprod.omega-test.test-app-backend-development"
	testRoleA     = "k8s.omega:role.identity-test-app-role"
	testRoleB     = "other.domain:role.reader"
)

type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pool *x509.CertPool
}

func newTestCA(t *testing.T) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test athenz ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return &testCA{cert: cert, key: key, pool: pool}
}

func (ca *testCA) sign(t *testing.T, tmpl *x509.Certificate, pub any) []byte {
	t.Helper()
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	require.NoError(t, err)
	tmpl.SerialNumber = serial
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, pub, ca.key)
	require.NoError(t, err)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func (ca *testCA) serviceCert(t *testing.T) (*ecdsa.PrivateKey, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	chain := ca.sign(t, &x509.Certificate{
		Subject:     pkix.Name{CommonName: testPrincipal},
		NotBefore:   time.Now().Add(-time.Minute),
		NotAfter:    time.Now().Add(24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}, key.Public())
	return key, chain
}

// fakeZTS is a TLS server standing in for the ZTS role certificate API.
type fakeZTS struct {
	t      *testing.T
	ca     *testCA
	server *httptest.Server
	caFile string

	mu        sync.Mutex
	status    int
	lifetime  time.Duration
	rawPEM    bool
	wrongKey  bool
	requests  int
	issuedFor []string
}

func newFakeZTS(t *testing.T, ca *testCA) *fakeZTS {
	t.Helper()
	z := &fakeZTS{t: t, ca: ca, status: http.StatusOK, lifetime: 2 * time.Hour}
	z.server = httptest.NewUnstartedServer(http.HandlerFunc(z.handle))
	z.server.TLS = &tls.Config{
		ClientAuth: tls.RequireAndVerifyClientCert,
		ClientCAs:  ca.pool,
	}
	z.server.StartTLS()
	t.Cleanup(z.server.Close)

	z.caFile = filepath.Join(t.TempDir(), "zts-ca.pem")
	require.NoError(t, os.WriteFile(z.caFile,
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: z.server.Certificate().Raw}), 0o600))
	return z
}

func (z *fakeZTS) set(fn func(z *fakeZTS)) {
	z.mu.Lock()
	defer z.mu.Unlock()
	fn(z)
}

func (z *fakeZTS) handle(w http.ResponseWriter, r *http.Request) {
	z.mu.Lock()
	defer z.mu.Unlock()
	z.requests++

	if !assert.Equal(z.t, "/zts/v1/rolecert", r.URL.Path) || !assert.Equal(z.t, http.MethodPost, r.Method) {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if !assert.NotEmpty(z.t, r.TLS.PeerCertificates) ||
		!assert.Equal(z.t, testPrincipal, r.TLS.PeerCertificates[0].Subject.CommonName,
			"ZTS must be called with the service certificate as the client certificate") {
		http.Error(w, "no client cert", http.StatusUnauthorized)
		return
	}
	if z.status != http.StatusOK {
		http.Error(w, `{"code":403,"message":"principal is not a member of the role"}`, z.status)
		return
	}

	var req map[string]any
	if !assert.NoError(z.t, json.NewDecoder(r.Body).Decode(&req)) {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	assert.EqualValues(z.t, 0, req["expiryTime"])
	block, _ := pem.Decode([]byte(req["csr"].(string)))
	if !assert.NotNil(z.t, block) {
		http.Error(w, "bad csr", http.StatusBadRequest)
		return
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if !assert.NoError(z.t, err) || !assert.NoError(z.t, csr.CheckSignature()) {
		http.Error(w, "bad csr", http.StatusBadRequest)
		return
	}

	domain, role, ok := strings.Cut(csr.Subject.CommonName, ":role.")
	assert.True(z.t, ok, "CSR CN %q must be <domain>:role.<role>", csr.Subject.CommonName)
	assert.Equal(z.t, []string{"US"}, csr.Subject.Country)
	assert.Equal(z.t, []string{"Yahoo"}, csr.Subject.Organization)
	var uris []string
	for _, u := range csr.URIs {
		uris = append(uris, u.String())
	}
	assert.Equal(z.t, []string{
		"spiffe://" + domain + "/ra/" + role,
		"athenz://principal/" + testPrincipal,
	}, uris)

	pub := csr.PublicKey
	if z.wrongKey {
		other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if !assert.NoError(z.t, err) {
			http.Error(w, "keygen", http.StatusInternalServerError)
			return
		}
		pub = other.Public()
	}
	certPEM := z.ca.sign(z.t, &x509.Certificate{
		Subject:     csr.Subject,
		URIs:        csr.URIs,
		NotBefore:   time.Now().Add(-time.Minute),
		NotAfter:    time.Now().Add(-time.Minute + z.lifetime),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}, pub)
	z.issuedFor = append(z.issuedFor, csr.Subject.CommonName)

	if z.rawPEM {
		_, _ = w.Write(certPEM)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"x509Certificate": string(certPEM)})
}

// readableMemoryFS adds the ReadFile the real stores provide.
type readableMemoryFS struct {
	*storage.MemoryFS
}

func (m readableMemoryFS) ReadFile(volumeID, name string) ([]byte, error) {
	files, err := m.ReadFiles(volumeID)
	if err != nil {
		return nil, err
	}
	data, ok := files[name]
	if !ok {
		return nil, storage.ErrNotFound
	}
	return data, nil
}

// dataFiles returns the volume's data files without csi-lib's metadata.json.
func dataFiles(t *testing.T, store readableMemoryFS, volumeID string) map[string][]byte {
	t.Helper()
	files, err := store.ReadFiles(volumeID)
	require.NoError(t, err)
	delete(files, "metadata.json")
	return files
}

func newRoleCertDriver(z *fakeZTS, store storage.Interface) *Driver {
	return &Driver{
		log:             klogr.New(),
		certFileName:    "crt.pem",
		keyFileName:     "key.pem",
		caFileName:      "ca.pem",
		store:           store,
		zts:             z.server.URL + "/zts/v1",
		caCertFile:      z.caFile,
		certCountryName: "US",
		certOrgName:     "Yahoo",
	}
}

func roleCertMeta(volumeID, roles string) metadata.Metadata {
	return metadata.Metadata{
		VolumeID:      volumeID,
		VolumeContext: map[string]string{attrRoleCerts: roles},
	}
}

func Test_parseRoleCerts(t *testing.T) {
	refs, err := parseRoleCerts(" k8s.omega:role.identity-test-app-role , ,other.domain:role.reader,k8s.omega:role.identity-test-app-role,")
	require.NoError(t, err)
	assert.Equal(t, []roleCertRef{
		{domain: "k8s.omega", role: "identity-test-app-role"},
		{domain: "other.domain", role: "reader"},
	}, refs)
	assert.Equal(t, "k8s.omega:role.identity-test-app-role.cert.pem", refs[0].certFileName())
	assert.Equal(t, "k8s.omega:role.identity-test-app-role.key.pem", refs[0].keyFileName())

	refs, err = parseRoleCerts("")
	require.NoError(t, err)
	assert.Empty(t, refs)

	refs, err = parseRoleCerts("a_b:role.c.d_e")
	require.NoError(t, err)
	assert.Equal(t, []roleCertRef{{domain: "a_b", role: "c.d_e"}}, refs)

	for _, bad := range []string{
		"k8s.omega",
		"k8s.omega:identity",
		":role.reader",
		"k8s.omega:role.",
		"../../etc:role.passwd",
		"..:role.x",
		".:role.x",
		"k8s.omega:role..",
		"k8s.omega:role../../../metadata.json",
		"k8s/omega:role.x",
		"k8s.omega:role.x/y",
		"k8s..omega:role.x",
		".k8s.omega:role.x",
		"k8s.omega.:role.x",
		"k8s.omega:role.x.",
		"k8s.omega:role.x:role.y",
		"k8s.omega:role.x y",
		"k8s.omega:role.x\x00",
		"k8s.omega:role.x\ny",
		"k8s.omega:role.-x",
		"k8s.omega:role." + strings.Repeat("a", 250),
		"good.domain:role.ok,bad/domain:role.x",
	} {
		_, err := parseRoleCerts(bad)
		assert.Error(t, err, "expected %q to be rejected", bad)
	}
}

func Test_roleCertFromResponse(t *testing.T) {
	pemBody := "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----"

	got, err := roleCertFromResponse([]byte(`{"x509Certificate":"` + strings.ReplaceAll(pemBody, "\n", `\n`) + `"}`))
	require.NoError(t, err)
	assert.Equal(t, pemBody, string(got))

	got, err = roleCertFromResponse([]byte("\n" + pemBody + "\n"))
	require.NoError(t, err)
	assert.Equal(t, pemBody+"\n", string(got))

	_, err = roleCertFromResponse([]byte(`{"x509Certificate":""}`))
	assert.Error(t, err)
	_, err = roleCertFromResponse([]byte(`not a cert`))
	assert.Error(t, err)
}

func Test_writeKeypair_roleCerts_firstIssuance(t *testing.T) {
	ca := newTestCA(t)
	z := newFakeZTS(t, ca)
	store := readableMemoryFS{storage.NewMemoryFS()}
	d := newRoleCertDriver(z, store)

	meta := roleCertMeta("vol-id", testRoleA+","+testRoleB)
	_, err := store.RegisterMetadata(meta)
	require.NoError(t, err)

	svcKey, svcChain := ca.serviceCert(t)
	before := time.Now()
	require.NoError(t, d.writeKeypair(meta, svcKey, svcChain, nil))

	assert.Equal(t, []string{testRoleA, testRoleB}, z.issuedFor)

	files, err := store.ReadFiles("vol-id")
	require.NoError(t, err)
	assert.Equal(t, svcChain, files["crt.pem"])
	for _, role := range []string{testRoleA, testRoleB} {
		pair, err := tls.X509KeyPair(files[role+".cert.pem"], files[role+".key.pem"])
		require.NoError(t, err, "role %s cert and key must be a matching pair", role)
		leaf, err := x509.ParseCertificate(pair.Certificate[0])
		require.NoError(t, err)
		assert.Equal(t, role, leaf.Subject.CommonName)
		_, err = leaf.Verify(x509.VerifyOptions{Roots: ca.pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}})
		require.NoError(t, err)

		block, _ := pem.Decode(files[role+".key.pem"])
		require.NotNil(t, block)
		assert.Equal(t, "PRIVATE KEY", block.Type)
	}
	assert.NotEqual(t, files[testRoleA+".key.pem"], files[testRoleB+".key.pem"], "each role must get its own key")
	assert.NotEqual(t, files["key.pem"], files[testRoleA+".key.pem"], "role keys must not reuse the service key")

	// 2h role cert issued a minute ago: renew at notBefore + 80m, well before the 24h default.
	updated, err := store.ReadMetadata("vol-id")
	require.NoError(t, err)
	require.NotNil(t, updated.NextIssuanceTime)
	want := before.Add(-time.Minute + 80*time.Minute)
	assert.WithinDuration(t, want, *updated.NextIssuanceTime, 5*time.Second)
}

func Test_writeKeypair_roleCerts_rawPEMResponse(t *testing.T) {
	ca := newTestCA(t)
	z := newFakeZTS(t, ca)
	z.set(func(z *fakeZTS) { z.rawPEM = true })
	store := readableMemoryFS{storage.NewMemoryFS()}
	d := newRoleCertDriver(z, store)

	meta := roleCertMeta("vol-id", testRoleA)
	_, err := store.RegisterMetadata(meta)
	require.NoError(t, err)

	svcKey, svcChain := ca.serviceCert(t)
	require.NoError(t, d.writeKeypair(meta, svcKey, svcChain, nil))

	files, err := store.ReadFiles("vol-id")
	require.NoError(t, err)
	_, err = tls.X509KeyPair(files[testRoleA+".cert.pem"], files[testRoleA+".key.pem"])
	require.NoError(t, err)
}

func Test_writeKeypair_roleCerts_firstIssuanceFailureReturnsError(t *testing.T) {
	ca := newTestCA(t)

	for name, setup := range map[string]func(z *fakeZTS, d *Driver){
		"zts forbidden":      func(z *fakeZTS, d *Driver) { z.set(func(z *fakeZTS) { z.status = http.StatusForbidden }) },
		"cert for other key": func(z *fakeZTS, d *Driver) { z.set(func(z *fakeZTS) { z.wrongKey = true }) },
		"untrusted server":   func(z *fakeZTS, d *Driver) { d.caCertFile = "" },
		"no zts configured":  func(z *fakeZTS, d *Driver) { d.zts = "" },
		"plain http zts":     func(z *fakeZTS, d *Driver) { d.zts = strings.Replace(d.zts, "https://", "http://", 1) },
	} {
		t.Run(name, func(t *testing.T) {
			z := newFakeZTS(t, ca)
			store := readableMemoryFS{storage.NewMemoryFS()}
			d := newRoleCertDriver(z, store)
			setup(z, d)

			meta := roleCertMeta("vol-id", testRoleA)
			_, err := store.RegisterMetadata(meta)
			require.NoError(t, err)

			svcKey, svcChain := ca.serviceCert(t)
			err = d.writeKeypair(meta, svcKey, svcChain, nil)
			require.Error(t, err)
			assert.Contains(t, err.Error(), testRoleA)

			assert.Empty(t, dataFiles(t, store, "vol-id"), "nothing may be written when a role certificate cannot be issued on first mount")
			updated, err := store.ReadMetadata("vol-id")
			require.NoError(t, err)
			assert.Nil(t, updated.NextIssuanceTime)
		})
	}
}

func Test_writeKeypair_roleCerts_renewalFailureCarriesPreviousFilesForward(t *testing.T) {
	ca := newTestCA(t)
	z := newFakeZTS(t, ca)
	store := readableMemoryFS{storage.NewMemoryFS()}
	d := newRoleCertDriver(z, store)

	meta := roleCertMeta("vol-id", testRoleA)
	_, err := store.RegisterMetadata(meta)
	require.NoError(t, err)

	svcKey1, svcChain1 := ca.serviceCert(t)
	require.NoError(t, d.writeKeypair(meta, svcKey1, svcChain1, nil))
	first, err := store.ReadFiles("vol-id")
	require.NoError(t, err)

	z.set(func(z *fakeZTS) { z.status = http.StatusInternalServerError })

	svcKey2, svcChain2 := ca.serviceCert(t)
	before := time.Now()
	require.NoError(t, d.writeKeypair(meta, svcKey2, svcChain2, nil),
		"a role renewal failure must not block service certificate renewal")

	second, err := store.ReadFiles("vol-id")
	require.NoError(t, err)
	assert.Equal(t, svcChain2, second["crt.pem"], "the new service certificate must be written")
	assert.Equal(t, first[testRoleA+".cert.pem"], second[testRoleA+".cert.pem"])
	assert.Equal(t, first[testRoleA+".key.pem"], second[testRoleA+".key.pem"])

	updated, err := store.ReadMetadata("vol-id")
	require.NoError(t, err)
	require.NotNil(t, updated.NextIssuanceTime)
	assert.WithinDuration(t, before.Add(roleCertRetryInterval), *updated.NextIssuanceTime, 5*time.Second,
		"a carried-forward role certificate must be retried soon, not after the full refresh interval")
}

func Test_writeKeypair_roleCerts_renewalFailsWithoutPreviousFiles(t *testing.T) {
	ca := newTestCA(t)
	z := newFakeZTS(t, ca)
	store := readableMemoryFS{storage.NewMemoryFS()}
	d := newRoleCertDriver(z, store)

	meta := roleCertMeta("vol-id", testRoleA+","+testRoleB)
	_, err := store.RegisterMetadata(meta)
	require.NoError(t, err)

	// Only role A exists on the volume.
	svcKey, svcChain := ca.serviceCert(t)
	require.NoError(t, d.writeKeypair(roleCertMeta("vol-id", testRoleA), svcKey, svcChain, nil))

	z.set(func(z *fakeZTS) { z.status = http.StatusForbidden })
	err = d.writeKeypair(meta, svcKey, svcChain, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), testRoleB)
}

func Test_writeKeypair_roleCerts_invalidAttribute(t *testing.T) {
	ca := newTestCA(t)
	z := newFakeZTS(t, ca)
	store := readableMemoryFS{storage.NewMemoryFS()}
	d := newRoleCertDriver(z, store)

	meta := roleCertMeta("vol-id", "k8s.omega:role.../../metadata.json")
	_, err := store.RegisterMetadata(meta)
	require.NoError(t, err)

	svcKey, svcChain := ca.serviceCert(t)
	require.Error(t, d.writeKeypair(meta, svcKey, svcChain, nil))
	assert.Zero(t, z.requests)

	assert.Empty(t, dataFiles(t, store, "vol-id"))
}

func Test_generateRequest_rejectsInvalidRoleCerts(t *testing.T) {
	d := &Driver{trustDomain: "athenz.io"}
	meta := metadata.Metadata{
		VolumeID: "vol-id",
		VolumeContext: map[string]string{
			"csi.storage.k8s.io/serviceAccount.tokens": `{"":{"token":"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InYwIn0.eyJhdWQiOlsiaHR0cHM6Ly96dHMuYXRoZW56LmlvL3p0cy92MSJdLCJleHAiOjIwMjYyMzY5NjIsImlhdCI6MTY5MDI0Njc5MywiaXNzIjoiaHR0cHM6Ly9rdWJlcm5ldGVzLmRlZmF1bHQuc3ZjLmNsdXN0ZXIubG9jYWwiLCJrdWJlcm5ldGVzLmlvIjp7Im5hbWVzcGFjZSI6InNhbmRib3giLCJwb2QiOnsibmFtZSI6Im15LWNzaS1hcHAtNTQ3OGM0ZDRjZC1nNjQ4ayIsInVpZCI6ImZlNWYwOWUxLTE3N2MtNGFjZS1iNzE5LWJmMjk5MmQ3MTAyNiJ9LCJzZXJ2aWNlYWNjb3VudCI6eyJuYW1lIjoiYXRoZW56LmV4YW1wbGUiLCJ1aWQiOiI2NGNhYjY2MC0wMjk2LTQ5MzItYmMxMC05ZWJlNWRkMzBlMjcifX0sIm5iZiI6MTY5MDI0Njc5Mywic3ViIjoic3lzdGVtOnNlcnZpY2VhY2NvdW50OnNhbmRib3g6YXRoZW56LmV4YW1wbGUifQ.sig","expirationTimestamp":"2023-07-13T01:16:41Z"}}`,
			attrRoleCerts: "../etc:role.passwd",
		},
	}

	_, err := d.generateRequest(meta)
	require.Error(t, err)
	assert.Contains(t, err.Error(), attrRoleCerts)

	meta.VolumeContext[attrRoleCerts] = testRoleA
	_, err = d.generateRequest(meta)
	require.NoError(t, err)
}

// inplaceReadableStore reads files back from the in-place writer's data
// directory, as *storage.Filesystem does in production.
type inplaceReadableStore struct {
	*inplaceWriteStorage
	dataPath string
}

func (s inplaceReadableStore) ReadFile(_, name string) ([]byte, error) {
	return os.ReadFile(filepath.Join(s.dataPath, name))
}

func Test_writeKeypair_roleCerts_inPlaceKeepsRoleFiles(t *testing.T) {
	ca := newTestCA(t)
	z := newFakeZTS(t, ca)
	inplace, dataPath := newTestInplaceStorage(t, "crt.pem")
	d := newRoleCertDriver(z, inplaceReadableStore{inplace, dataPath})

	meta := roleCertMeta("vol-id", testRoleA)
	roleCert := filepath.Join(dataPath, testRoleA+".cert.pem")
	roleKey := filepath.Join(dataPath, testRoleA+".key.pem")
	allNames := []string{"crt.pem", "key.pem", testRoleA + ".cert.pem", testRoleA + ".key.pem"}

	svcKey, svcChain := ca.serviceCert(t)
	require.NoError(t, d.writeKeypair(meta, svcKey, svcChain, nil))
	inode := inodeOf(t, roleCert)
	firstCert, err := os.ReadFile(roleCert)
	require.NoError(t, err)
	firstKey, err := os.ReadFile(roleKey)
	require.NoError(t, err)

	t.Run("renewal rewrites role files in place", func(t *testing.T) {
		makeWritableForRewrite(t, dataPath, allNames...)
		svcKey, svcChain := ca.serviceCert(t)
		require.NoError(t, d.writeKeypair(meta, svcKey, svcChain, nil))

		assert.Equal(t, inode, inodeOf(t, roleCert))
		got, err := os.ReadFile(roleCert)
		require.NoError(t, err)
		assert.NotEqual(t, firstCert, got)
		firstCert = got
		firstKey, err = os.ReadFile(roleKey)
		require.NoError(t, err)
	})

	t.Run("failed renewal keeps role files", func(t *testing.T) {
		z.set(func(z *fakeZTS) { z.status = http.StatusServiceUnavailable })
		makeWritableForRewrite(t, dataPath, allNames...)
		svcKey, svcChain := ca.serviceCert(t)
		require.NoError(t, d.writeKeypair(meta, svcKey, svcChain, nil))

		assert.Equal(t, inode, inodeOf(t, roleCert))
		got, err := os.ReadFile(roleCert)
		require.NoError(t, err)
		assert.Equal(t, firstCert, got)
		got, err = os.ReadFile(roleKey)
		require.NoError(t, err)
		assert.Equal(t, firstKey, got)
		got, err = os.ReadFile(filepath.Join(dataPath, "crt.pem"))
		require.NoError(t, err)
		assert.Equal(t, svcChain, got)
	})
}

func Test_updateRootCAFiles_atomicDirPreservesRoleFiles(t *testing.T) {
	store := newFakeCAStore("vol-id", map[string][]byte{
		"tls.crt":               []byte("cert-1"),
		"tls.key":               []byte("key-1"),
		"ca.crt":                []byte("ca-old"),
		testRoleA + ".cert.pem": []byte("role-cert-1"),
		testRoleA + ".key.pem":  []byte("role-key-1"),
	})
	store.volumeContext = map[string]string{attrRoleCerts: testRoleA}

	require.NoError(t, newTestCAManager(store, "ca-new").updateRootCAFiles())

	require.Len(t, store.writeFilesPayloads, 1)
	assert.Equal(t, map[string][]byte{
		"tls.crt":               []byte("cert-1"),
		"tls.key":               []byte("key-1"),
		"ca.crt":                []byte("ca-new"),
		testRoleA + ".cert.pem": []byte("role-cert-1"),
		testRoleA + ".key.pem":  []byte("role-key-1"),
	}, store.writeFilesPayloads[0])
}

func Test_updateRootCAFiles_atomicDirErrorsWhenRoleFileIsUnreadable(t *testing.T) {
	store := newFakeCAStore("vol-id", map[string][]byte{
		"tls.crt":               []byte("cert-1"),
		"tls.key":               []byte("key-1"),
		"ca.crt":                []byte("ca-old"),
		testRoleA + ".cert.pem": []byte("role-cert-1"),
	})
	store.volumeContext = map[string]string{attrRoleCerts: testRoleA}

	require.Error(t, newTestCAManager(store, "ca-new").updateRootCAFiles())
	assert.Empty(t, store.writeFilesPayloads)
}

func Test_updateRootCAFiles_inPlaceLeavesRoleFilesAlone(t *testing.T) {
	inner := newFakeCAStore("vol-id", map[string][]byte{
		"tls.crt":               []byte("cert-1"),
		"tls.key":               []byte("key-1"),
		"ca.crt":                []byte("ca-old"),
		testRoleA + ".cert.pem": []byte("role-cert-1"),
		testRoleA + ".key.pem":  []byte("role-key-1"),
	})
	inner.volumeContext = map[string]string{attrRoleCerts: testRoleA}
	store := &fakeSingleFileCAStore{fakeCAStore: inner}

	require.NoError(t, newTestCAManager(store, "ca-new").updateRootCAFiles())

	assert.Empty(t, inner.writeFilesPayloads)
	require.Len(t, store.singleWrites, 1)
	assert.Equal(t, "ca.crt", store.singleWrites[0].name)
	assert.Equal(t, []byte("role-cert-1"), inner.files["vol-id"][testRoleA+".cert.pem"])
	assert.Equal(t, []byte("role-key-1"), inner.files["vol-id"][testRoleA+".key.pem"])
}

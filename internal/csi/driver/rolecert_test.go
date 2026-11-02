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

type fakeZTS struct {
	t      *testing.T
	ca     *testCA
	server *httptest.Server
	caFile string

	mu        sync.Mutex
	status    int
	issuedFor []string
}

func newFakeZTS(t *testing.T, ca *testCA) *fakeZTS {
	t.Helper()
	z := &fakeZTS{t: t, ca: ca, status: http.StatusOK}
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

	if !assert.NotEmpty(z.t, r.TLS.PeerCertificates) ||
		!assert.Equal(z.t, testPrincipal, r.TLS.PeerCertificates[0].Subject.CommonName) {
		http.Error(w, "no client cert", http.StatusUnauthorized)
		return
	}
	if z.status != http.StatusOK {
		http.Error(w, "forbidden", z.status)
		return
	}

	var req struct {
		CSR string `json:"csr"`
	}
	block, _ := pem.Decode(nil)
	if err := json.NewDecoder(r.Body).Decode(&req); err == nil {
		block, _ = pem.Decode([]byte(req.CSR))
	}
	if block == nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if !assert.NoError(z.t, err) {
		http.Error(w, "bad csr", http.StatusBadRequest)
		return
	}

	domain, role, ok := strings.Cut(csr.Subject.CommonName, ":role.")
	assert.True(z.t, ok, "CSR CN %q must be <domain>:role.<role>", csr.Subject.CommonName)
	var uris []string
	for _, u := range csr.URIs {
		uris = append(uris, u.String())
	}
	assert.Equal(z.t, []string{
		"spiffe://" + domain + "/ra/" + role,
		"athenz://principal/" + testPrincipal,
	}, uris)

	certPEM := z.ca.sign(z.t, &x509.Certificate{
		Subject:     csr.Subject,
		URIs:        csr.URIs,
		NotBefore:   time.Now().Add(-time.Minute),
		NotAfter:    time.Now().Add(-time.Minute + 2*time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}, csr.PublicKey)
	z.issuedFor = append(z.issuedFor, csr.Subject.CommonName)

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
	tests := map[string]struct {
		in      string
		want    []roleCertRef
		wantErr bool
	}{
		"valid single": {in: testRoleA, want: []roleCertRef{{domain: "k8s.omega", role: "identity-test-app-role"}}},
		"multiple with spaces and duplicate": {
			in: " " + testRoleA + " , ," + testRoleB + "," + testRoleA + ",",
			want: []roleCertRef{
				{domain: "k8s.omega", role: "identity-test-app-role"},
				{domain: "other.domain", role: "reader"},
			},
		},
		"empty":           {in: ""},
		"missing :role.":  {in: "k8s.omega:identity", wantErr: true},
		"traversal dots":  {in: "k8s.omega:role../../../metadata.json", wantErr: true},
		"traversal slash": {in: "k8s/omega:role.x", wantErr: true},
		"name too long":   {in: "k8s.omega:role." + strings.Repeat("a", 250), wantErr: true},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			refs, err := parseRoleCerts(tc.in)
			if tc.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, refs)
		})
	}
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

	// 2h role cert issued a minute ago: renew at notBefore + 80m (2/3 of lifetime).
	updated, err := store.ReadMetadata("vol-id")
	require.NoError(t, err)
	require.NotNil(t, updated.NextIssuanceTime)
	want := before.Add(-time.Minute + 80*time.Minute)
	assert.WithinDuration(t, want, *updated.NextIssuanceTime, 5*time.Second)
}

func Test_writeKeypair_roleCerts_failureWithoutPreviousFilesReturnsError(t *testing.T) {
	ca := newTestCA(t)

	for name, setup := range map[string]func(z *fakeZTS, d *Driver){
		"zts forbidden":     func(z *fakeZTS, d *Driver) { z.set(func(z *fakeZTS) { z.status = http.StatusForbidden }) },
		"no zts configured": func(z *fakeZTS, d *Driver) { d.zts = "" },
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

			assert.Empty(t, dataFiles(t, store, "vol-id"))
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
	assert.WithinDuration(t, before.Add(roleCertRetryInterval), *updated.NextIssuanceTime, 5*time.Second)
	assert.False(t, updated.NextIssuanceTime.After(time.Now().Add(roleCertRetryInterval)))
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
	allNames := []string{"crt.pem", "key.pem", testRoleA + ".cert.pem", testRoleA + ".key.pem"}

	svcKey, svcChain := ca.serviceCert(t)
	require.NoError(t, d.writeKeypair(meta, svcKey, svcChain, nil))
	inode := inodeOf(t, roleCert)
	firstCert, err := os.ReadFile(roleCert)
	require.NoError(t, err)

	makeWritableForRewrite(t, dataPath, allNames...)
	svcKey, svcChain = ca.serviceCert(t)
	require.NoError(t, d.writeKeypair(meta, svcKey, svcChain, nil))

	assert.Equal(t, inode, inodeOf(t, roleCert))
	got, err := os.ReadFile(roleCert)
	require.NoError(t, err)
	assert.NotEqual(t, firstCert, got)
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

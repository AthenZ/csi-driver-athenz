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
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
	"time"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	utilpki "github.com/cert-manager/cert-manager/pkg/util/pki"
	"github.com/cert-manager/csi-lib/metadata"
	"github.com/cert-manager/csi-lib/storage"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/stretchr/testify/require"
	"k8s.io/klog/v2/klogr"

	"github.com/AthenZ/csi-driver-athenz/internal/csi/rootca"
)

// Ensure writeKeyPair is compatible with go-spiffe/v2 x509svid.Parse.
func Test_writeKeyPair(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() {
		cancel()
	})

	capk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	caTmpl, err := utilpki.CertificateTemplateFromCertificate(&cmapi.Certificate{Spec: cmapi.CertificateSpec{CommonName: "my-ca"}})
	require.NoError(t, err)

	caPEM, ca, err := utilpki.SignCertificate(caTmpl, caTmpl, capk.Public(), capk)
	require.NoError(t, err)

	leafpk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	leafTmpl, err := utilpki.CertificateTemplateFromCertificate(
		&cmapi.Certificate{
			Spec: cmapi.CertificateSpec{URIs: []string{"spiffe://athenz.io/ns/sandbox/sa/default"}},
		},
	)
	require.NoError(t, err)

	leafPEM, _, err := utilpki.SignCertificate(leafTmpl, ca, leafpk.Public(), capk)
	require.NoError(t, err)

	ch := make(chan []byte)
	rootCAs := rootca.NewMemory(ctx, ch)
	ch <- caPEM

	store := storage.NewMemoryFS()
	d := &Driver{
		log:          klogr.New(),
		certFileName: "crt.pem",
		keyFileName:  "key.pem",
		caFileName:   "ca.pem",
		rootCAs:      rootCAs,
		store:        store,
	}

	meta := metadata.Metadata{VolumeID: "vol-id"}

	_, err = store.RegisterMetadata(meta)
	require.NoError(t, err)

	err = d.writeKeypair(meta, leafpk, leafPEM, nil)
	require.NoError(t, err)

	files, err := store.ReadFiles("vol-id")
	require.NoError(t, err)

	_, err = x509svid.Parse(files["crt.pem"], files["key.pem"])
	require.NoError(t, err)
}

func Test_driverOptions(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() {
		cancel()
	})

	capk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	caTmpl, err := utilpki.CertificateTemplateFromCertificate(&cmapi.Certificate{Spec: cmapi.CertificateSpec{CommonName: "my-ca"}})
	require.NoError(t, err)

	caPEM, _, err := utilpki.SignCertificate(caTmpl, caTmpl, capk.Public(), capk)
	require.NoError(t, err)

	ch := make(chan []byte)
	rootCAs := rootca.NewMemory(ctx, ch)
	ch <- caPEM

	store := storage.NewMemoryFS()
	d := &Driver{
		certFileName: "crt.pem",
		keyFileName:  "key.pem",
		caFileName:   "ca.pem",
		rootCAs:      rootCAs,
		store:        store,
	}
	volumeContext := make(map[string]string)

	volumeContext["csi.storage.k8s.io/serviceAccount.tokens"] = "{\"\":{\"token\":\"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InYwIn0.eyJhdWQiOlsiaHR0cHM6Ly96dHMuYXRoZW56LmlvL3p0cy92MSJdLCJleHAiOjIwMjYyMzY5NjIsImlhdCI6MTY5MDI0Njc5MywiaXNzIjoiaHR0cHM6Ly9rdWJlcm5ldGVzLmRlZmF1bHQuc3ZjLmNsdXN0ZXIubG9jYWwiLCJrdWJlcm5ldGVzLmlvIjp7Im5hbWVzcGFjZSI6InNhbmRib3giLCJwb2QiOnsibmFtZSI6Im15LWNzaS1hcHAtNTQ3OGM0ZDRjZC1nNjQ4ayIsInVpZCI6ImZlNWYwOWUxLTE3N2MtNGFjZS1iNzE5LWJmMjk5MmQ3MTAyNiJ9LCJzZXJ2aWNlYWNjb3VudCI6eyJuYW1lIjoiYXRoZW56LmV4YW1wbGUiLCJ1aWQiOiI2NGNhYjY2MC0wMjk2LTQ5MzItYmMxMC05ZWJlNWRkMzBlMjcifX0sIm5iZiI6MTY5MDI0Njc5Mywic3ViIjoic3lzdGVtOnNlcnZpY2VhY2NvdW50OnNhbmRib3g6YXRoZW56LmV4YW1wbGUifQ.d1tHGEA1xCFhCxwecl9qGoR2aWSYy9tOGBNgipoaeim7XltqdEDpLbKbVOLvdgcLOGHPxEb4FTs6kpn8hJSSdA-qpVW09pvxzCjutCcF8RJWNgbajzzsAk5YUT_i0deE6xk7gD8E7jwRCm7g7JY10_mva69eyon45e0K9tWR2kvoA1KKmTFbOFwcRNNVuuhc95pLx-3e4Dm8FKT7JjJUyHXjINmQ3pKCHrVDLBTLFKh6tYH1xzIm6bkIXVxYb2hiQzl-L0R_yyEtXQCatWc2lTuM8ObsfQD3Gp_WzWe_H3-8DBXRHBcowmNQfu3S6-8ykfeXMO281xOMjk7LZRMCTw\",\"expirationTimestamp\":\"2023-07-13T01:16:41Z\"}}"

	meta := metadata.Metadata{
		VolumeID:      "vol-id",
		VolumeContext: volumeContext,
	}

	_, err = store.RegisterMetadata(meta)
	require.NoError(t, err)

	certBundle, err := d.generateRequest(meta)
	require.NoError(t, err)

	csr := certBundle.Request
	require.NotNil(t, csr)
	expectedDNSNames := []string{"example.sandbox.svc.cluster.local", "example.sandbox.svc"}
	require.Equalf(t, expectedDNSNames, csr.DNSNames, "expected %d DNS names in CSR, got %d", expectedDNSNames, csr.DNSNames)
}

func Test_generateRequestWithNamespaceDomain(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() {
		cancel()
	})

	capk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	caTmpl, err := utilpki.CertificateTemplateFromCertificate(&cmapi.Certificate{Spec: cmapi.CertificateSpec{CommonName: "my-ca"}})
	require.NoError(t, err)

	caPEM, _, err := utilpki.SignCertificate(caTmpl, caTmpl, capk.Public(), capk)
	require.NoError(t, err)

	ch := make(chan []byte)
	rootCAs := rootca.NewMemory(ctx, ch)
	ch <- caPEM

	store := storage.NewMemoryFS()
	d := &Driver{
		trustDomain:  "athenz.io",
		certFileName: "crt.pem",
		keyFileName:  "key.pem",
		caFileName:   "ca.pem",
		rootCAs:      rootCAs,
		store:        store,
	}

	volumeContext := make(map[string]string)
	volumeContext["csi.storage.k8s.io/serviceAccount.tokens"] = "{\"\":{\"token\":\"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InYwIn0.eyJhdWQiOlsiaHR0cHM6Ly96dHMuYXRoZW56LmlvL3p0cy92MSJdLCJleHAiOjIwMjYyMzY5NjIsImlhdCI6MTY5MDI0Njc5MywiaXNzIjoiaHR0cHM6Ly9rdWJlcm5ldGVzLmRlZmF1bHQuc3ZjLmNsdXN0ZXIubG9jYWwiLCJrdWJlcm5ldGVzLmlvIjp7Im5hbWVzcGFjZSI6InByb2QiLCJwb2QiOnsibmFtZSI6Im15LWNzaS1hcHAtNTQ3OGM0ZDRjZC1nNjQ4ayIsInVpZCI6ImZlNWYwOWUxLTE3N2MtNGFjZS1iNzE5LWJmMjk5MmQ3MTAyNiJ9LCJzZXJ2aWNlYWNjb3VudCI6eyJuYW1lIjoiYXBpIiwidWlkIjoiNjRjYWI2NjAtMDI5Ni00OTMyLWJjMTAtOWViZTVkZDMwZTI3In19LCJuYmYiOjE2OTAyNDY3OTMsInN1YiI6InN5c3RlbTpzZXJ2aWNlYWNjb3VudDpwcm9kOmFwaSJ9.d1tHGEA1xCFhCxwecl9qGoR2aWSYy9tOGBNgipoaeim7XltqdEDpLbKbVOLvdgcLOGHPxEb4FTs6kpn8hJSSdA-qpVW09pvxzCjutCcF8RJWNgbajzzsAk5YUT_i0deE6xk7gD8E7jwRCm7g7JY10_mva69eyon45e0K9tWR2kvoA1KKmTFbOFwcRNNVuuhc95pLx-3e4Dm8FKT7JjJUyHXjINmQ3pKCHrVDLBTLFKh6tYH1xzIm6bkIXVxYb2hiQzl-L0R_yyEtXQCatWc2lTuM8ObsfQD3Gp_WzWe_H3-8DBXRHBcowmNQfu3S6-8ykfeXMO281xOMjk7LZRMCTw\",\"expirationTimestamp\":\"2023-07-13T01:16:41Z\"}}"
	volumeContext["csi.cert-manager.athenz.io/use-namespace-for-domain"] = "true"

	meta := metadata.Metadata{
		VolumeID:      "vol-id",
		VolumeContext: volumeContext,
	}

	_, err = store.RegisterMetadata(meta)
	require.NoError(t, err)

	// This test will fail because getNamespaceAnnotations tries to get in-cluster config
	// which won't be available in unit tests, but we can verify the logic path is taken
	_, err = d.generateRequest(meta)
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to get domain namespace annotations")
}

func Test_generateRequestWithoutNamespaceDomain(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() {
		cancel()
	})

	capk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	caTmpl, err := utilpki.CertificateTemplateFromCertificate(&cmapi.Certificate{Spec: cmapi.CertificateSpec{CommonName: "my-ca"}})
	require.NoError(t, err)

	caPEM, _, err := utilpki.SignCertificate(caTmpl, caTmpl, capk.Public(), capk)
	require.NoError(t, err)

	ch := make(chan []byte)
	rootCAs := rootca.NewMemory(ctx, ch)
	ch <- caPEM

	store := storage.NewMemoryFS()
	d := &Driver{
		trustDomain:  "athenz.io",
		certFileName: "crt.pem",
		keyFileName:  "key.pem",
		caFileName:   "ca.pem",
		rootCAs:      rootCAs,
		store:        store,
	}

	volumeContext := make(map[string]string)
	volumeContext["csi.storage.k8s.io/serviceAccount.tokens"] = "{\"\":{\"token\":\"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InYwIn0.eyJhdWQiOlsiaHR0cHM6Ly96dHMuYXRoZW56LmlvL3p0cy92MSJdLCJleHAiOjIwMjYyMzY5NjIsImlhdCI6MTY5MDI0Njc5MywiaXNzIjoiaHR0cHM6Ly9rdWJlcm5ldGVzLmRlZmF1bHQuc3ZjLmNsdXN0ZXIubG9jYWwiLCJrdWJlcm5ldGVzLmlvIjp7Im5hbWVzcGFjZSI6InNhbmRib3giLCJwb2QiOnsibmFtZSI6Im15LWNzaS1hcHAtNTQ3OGM0ZDRjZC1nNjQ4ayIsInVpZCI6ImZlNWYwOWUxLTE3N2MtNGFjZS1iNzE5LWJmMjk5MmQ3MTAyNiJ9LCJzZXJ2aWNlYWNjb3VudCI6eyJuYW1lIjoiYXRoZW56LmV4YW1wbGUiLCJ1aWQiOiI2NGNhYjY2MC0wMjk2LTQ5MzItYmMxMC05ZWJlNWRkMzBlMjcifX0sIm5iZiI6MTY5MDI0Njc5Mywic3ViIjoic3lzdGVtOnNlcnZpY2VhY2NvdW50OnNhbmRib3g6YXRoZW56LmV4YW1wbGUifQ.d1tHGEA1xCFhCxwecl9qGoR2aWSYy9tOGBNgipoaeim7XltqdEDpLbKbVOLvdgcLOGHPxEb4FTs6kpn8hJSSdA-qpVW09pvxzCjutCcF8RJWNgbajzzsAk5YUT_i0deE6xk7gD8E7jwRCm7g7JY10_mva69eyon45e0K9tWR2kvoA1KKmTFbOFwcRNNVuuhc95pLx-3e4Dm8FKT7JjJUyHXjINmQ3pKCHrVDLBTLFKh6tYH1xzIm6bkIXVxYb2hiQzl-L0R_yyEtXQCatWc2lTuM8ObsfQD3Gp_WzWe_H3-8DBXRHBcowmNQfu3S6-8ykfeXMO281xOMjk7LZRMCTw\",\"expirationTimestamp\":\"2023-07-13T01:16:41Z\"}}"
	// Note: use-namespace-for-domain is not set, so it should use the default behavior

	meta := metadata.Metadata{
		VolumeID:      "vol-id",
		VolumeContext: volumeContext,
	}

	_, err = store.RegisterMetadata(meta)
	require.NoError(t, err)

	certBundle, err := d.generateRequest(meta)
	require.NoError(t, err)

	csr := certBundle.Request
	require.NotNil(t, csr)

	// Should use the default behavior (extract domain from service account name)
	expectedDNSNames := []string{"example.sandbox.svc.cluster.local", "example.sandbox.svc"}
	require.Equalf(t, expectedDNSNames, csr.DNSNames, "expected %d DNS names in CSR, got %d", expectedDNSNames, csr.DNSNames)

	// Should have the default spiffe ID format
	expectedSpiffeID := "spiffe://athenz.io/ns/sandbox/sa/athenz.example"
	require.Equal(t, expectedSpiffeID, certBundle.Annotations["csi.cert-manager.athenz.io/identity"])
}

func Test_generateRequestWithNamespaceDomainFalse(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() {
		cancel()
	})

	capk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	caTmpl, err := utilpki.CertificateTemplateFromCertificate(&cmapi.Certificate{Spec: cmapi.CertificateSpec{CommonName: "my-ca"}})
	require.NoError(t, err)

	caPEM, _, err := utilpki.SignCertificate(caTmpl, caTmpl, capk.Public(), capk)
	require.NoError(t, err)

	ch := make(chan []byte)
	rootCAs := rootca.NewMemory(ctx, ch)
	ch <- caPEM

	store := storage.NewMemoryFS()
	d := &Driver{
		trustDomain:  "athenz.io",
		certFileName: "crt.pem",
		keyFileName:  "key.pem",
		caFileName:   "ca.pem",
		rootCAs:      rootCAs,
		store:        store,
	}

	volumeContext := make(map[string]string)
	volumeContext["csi.storage.k8s.io/serviceAccount.tokens"] = "{\"\":{\"token\":\"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InYwIn0.eyJhdWQiOlsiaHR0cHM6Ly96dHMuYXRoZW56LmlvL3p0cy92MSJdLCJleHAiOjIwMjYyMzY5NjIsImlhdCI6MTY5MDI0Njc5MywiaXNzIjoiaHR0cHM6Ly9rdWJlcm5ldGVzLmRlZmF1bHQuc3ZjLmNsdXN0ZXIubG9jYWwiLCJrdWJlcm5ldGVzLmlvIjp7Im5hbWVzcGFjZSI6InNhbmRib3giLCJwb2QiOnsibmFtZSI6Im15LWNzaS1hcHAtNTQ3OGM0ZDRjZC1nNjQ4ayIsInVpZCI6ImZlNWYwOWUxLTE3N2MtNGFjZS1iNzE5LWJmMjk5MmQ3MTAyNiJ9LCJzZXJ2aWNlYWNjb3VudCI6eyJuYW1lIjoiYXRoZW56LmV4YW1wbGUiLCJ1aWQiOiI2NGNhYjY2MC0wMjk2LTQ5MzItYmMxMC05ZWJlNWRkMzBlMjcifX0sIm5iZiI6MTY5MDI0Njc5Mywic3ViIjoic3lzdGVtOnNlcnZpY2VhY2NvdW50OnNhbmRib3g6YXRoZW56LmV4YW1wbGUifQ.d1tHGEA1xCFhCxwecl9qGoR2aWSYy9tOGBNgipoaeim7XltqdEDpLbKbVOLvdgcLOGHPxEb4FTs6kpn8hJSSdA-qpVW09pvxzCjutCcF8RJWNgbajzzsAk5YUT_i0deE6xk7gD8E7jwRCm7g7JY10_mva69eyon45e0K9tWR2kvoA1KKmTFbOFwcRNNVuuhc95pLx-3e4Dm8FKT7JjJUyHXjINmQ3pKCHrVDLBTLFKh6tYH1xzIm6bkIXVxYb2hiQzl-L0R_yyEtXQCatWc2lTuM8ObsfQD3Gp_WzWe_H3-8DBXRHBcowmNQfu3S6-8ykfeXMO281xOMjk7LZRMCTw\",\"expirationTimestamp\":\"2023-07-13T01:16:41Z\"}}"
	volumeContext["csi.cert-manager.athenz.io/use-namespace-for-domain"] = "false"

	meta := metadata.Metadata{
		VolumeID:      "vol-id",
		VolumeContext: volumeContext,
	}

	_, err = store.RegisterMetadata(meta)
	require.NoError(t, err)

	certBundle, err := d.generateRequest(meta)
	require.NoError(t, err)

	csr := certBundle.Request
	require.NotNil(t, csr)

	// Should use the default behavior (extract domain from service account name)
	expectedDNSNames := []string{"example.sandbox.svc.cluster.local", "example.sandbox.svc"}
	require.Equalf(t, expectedDNSNames, csr.DNSNames, "expected %d DNS names in CSR, got %d", expectedDNSNames, csr.DNSNames)

	// Should have the default spiffe ID format
	expectedSpiffeID := "spiffe://athenz.io/ns/sandbox/sa/athenz.example"
	require.Equal(t, expectedSpiffeID, certBundle.Annotations["csi.cert-manager.athenz.io/identity"])
}

func Test_writeKeyPairWithCustomRefreshInterval(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() {
		cancel()
	})

	capk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	caTmpl, err := utilpki.CertificateTemplateFromCertificate(&cmapi.Certificate{Spec: cmapi.CertificateSpec{CommonName: "my-ca"}})
	require.NoError(t, err)

	caPEM, ca, err := utilpki.SignCertificate(caTmpl, caTmpl, capk.Public(), capk)
	require.NoError(t, err)

	leafpk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	leafTmpl, err := utilpki.CertificateTemplateFromCertificate(
		&cmapi.Certificate{
			Spec: cmapi.CertificateSpec{URIs: []string{"spiffe://athenz.io/ns/sandbox/sa/default"}},
		},
	)
	require.NoError(t, err)

	leafPEM, _, err := utilpki.SignCertificate(leafTmpl, ca, leafpk.Public(), capk)
	require.NoError(t, err)

	ch := make(chan []byte)
	rootCAs := rootca.NewMemory(ctx, ch)
	ch <- caPEM

	store := storage.NewMemoryFS()
	d := &Driver{
		log:          klogr.New(),
		certFileName: "crt.pem",
		keyFileName:  "key.pem",
		caFileName:   "ca.pem",
		rootCAs:      rootCAs,
		store:        store,
	}

	// Test with custom refresh interval of 12 hours
	volumeContext := map[string]string{
		"csi.cert-manager.athenz.io/refresh-interval": "12h",
	}
	meta := metadata.Metadata{VolumeID: "vol-id-refresh", VolumeContext: volumeContext}

	_, err = store.RegisterMetadata(meta)
	require.NoError(t, err)

	beforeWrite := time.Now()
	err = d.writeKeypair(meta, leafpk, leafPEM, nil)
	require.NoError(t, err)
	afterWrite := time.Now()

	files, err := store.ReadFiles("vol-id-refresh")
	require.NoError(t, err)

	_, err = x509svid.Parse(files["crt.pem"], files["key.pem"])
	require.NoError(t, err)

	// Verify the next issuance time is approximately 12 hours from now
	updatedMeta, err := store.ReadMetadata("vol-id-refresh")
	require.NoError(t, err)
	require.NotNil(t, updatedMeta.NextIssuanceTime)

	expectedMin := beforeWrite.Add(12 * time.Hour)
	expectedMax := afterWrite.Add(12 * time.Hour)
	require.True(t, updatedMeta.NextIssuanceTime.After(expectedMin) || updatedMeta.NextIssuanceTime.Equal(expectedMin),
		"NextIssuanceTime should be >= now + 12h")
	require.True(t, updatedMeta.NextIssuanceTime.Before(expectedMax) || updatedMeta.NextIssuanceTime.Equal(expectedMax),
		"NextIssuanceTime should be <= now + 12h")
}

func Test_writeKeyPairWithDefaultRefreshInterval(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() {
		cancel()
	})

	capk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	caTmpl, err := utilpki.CertificateTemplateFromCertificate(&cmapi.Certificate{Spec: cmapi.CertificateSpec{CommonName: "my-ca"}})
	require.NoError(t, err)

	caPEM, ca, err := utilpki.SignCertificate(caTmpl, caTmpl, capk.Public(), capk)
	require.NoError(t, err)

	leafpk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	leafTmpl, err := utilpki.CertificateTemplateFromCertificate(
		&cmapi.Certificate{
			Spec: cmapi.CertificateSpec{URIs: []string{"spiffe://athenz.io/ns/sandbox/sa/default"}},
		},
	)
	require.NoError(t, err)

	leafPEM, _, err := utilpki.SignCertificate(leafTmpl, ca, leafpk.Public(), capk)
	require.NoError(t, err)

	ch := make(chan []byte)
	rootCAs := rootca.NewMemory(ctx, ch)
	ch <- caPEM

	store := storage.NewMemoryFS()
	d := &Driver{
		log:          klogr.New(),
		certFileName: "crt.pem",
		keyFileName:  "key.pem",
		caFileName:   "ca.pem",
		rootCAs:      rootCAs,
		store:        store,
	}

	// Test without custom refresh interval (should use certificate-based calculation)
	meta := metadata.Metadata{VolumeID: "vol-id-default"}

	_, err = store.RegisterMetadata(meta)
	require.NoError(t, err)

	err = d.writeKeypair(meta, leafpk, leafPEM, nil)
	require.NoError(t, err)

	files, err := store.ReadFiles("vol-id-default")
	require.NoError(t, err)

	_, err = x509svid.Parse(files["crt.pem"], files["key.pem"])
	require.NoError(t, err)

	// Verify the next issuance time was set (based on certificate validity)
	updatedMeta, err := store.ReadMetadata("vol-id-default")
	require.NoError(t, err)
	require.NotNil(t, updatedMeta.NextIssuanceTime)
}

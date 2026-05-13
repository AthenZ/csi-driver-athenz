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
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"testing"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	utilpki "github.com/cert-manager/cert-manager/pkg/util/pki"
	"github.com/cert-manager/csi-lib/metadata"
	"github.com/cert-manager/csi-lib/storage"
	keystore "github.com/pavlo-v-chernykh/keystore-go/v4"
	"github.com/stretchr/testify/require"
	pkcs12 "software.sslmate.com/src/go-pkcs12"

	"github.com/AthenZ/csi-driver-athenz/internal/csi/rootca"
)

// keystoreFixture builds a CA-signed leaf cert/key pair plus a wired-up
// Driver writing into an in-memory store. The concrete *MemoryFS is also
// returned so tests can read files back via ReadFiles, which is not part of
// the storage.Interface contract.
func keystoreFixture(t *testing.T, opts ...func(*Driver)) (*ecdsa.PrivateKey, []byte, *Driver, *storage.MemoryFS, metadata.Metadata) {
	t.Helper()

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	capk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	caTmpl, err := utilpki.CertificateTemplateFromCertificate(&cmapi.Certificate{
		Spec: cmapi.CertificateSpec{CommonName: "my-ca"},
	})
	require.NoError(t, err)

	caPEM, ca, err := utilpki.SignCertificate(caTmpl, caTmpl, capk.Public(), capk)
	require.NoError(t, err)

	leafpk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	leafTmpl, err := utilpki.CertificateTemplateFromCertificate(&cmapi.Certificate{
		Spec: cmapi.CertificateSpec{
			URIs: []string{"spiffe://athenz.io/ns/sandbox/sa/default"},
		},
	})
	require.NoError(t, err)

	leafPEM, _, err := utilpki.SignCertificate(leafTmpl, ca, leafpk.Public(), capk)
	require.NoError(t, err)

	ch := make(chan []byte, 1)
	rootCAs := rootca.NewMemory(ctx, ch)
	ch <- caPEM

	store := storage.NewMemoryFS()
	d := &Driver{
		certFileName:     "tls.crt",
		keyFileName:      "tls.key",
		caFileName:       "ca.crt",
		keystoreEnabled:  true,
		keystoreFileName: "service.pkcs12",
		jksFileName:      "service.jks",
		keystorePassword: "changeit",
		keystoreAlias:    "service",
		rootCAs:          rootCAs,
		store:            store,
	}
	for _, opt := range opts {
		opt(d)
	}

	meta := metadata.Metadata{VolumeID: "vol-id"}
	_, err = store.RegisterMetadata(meta)
	require.NoError(t, err)

	return leafpk, leafPEM, d, store, meta
}

// Test_writeKeypair_PKCS12 verifies the PKCS12 keystore decodes back to the
// same private key and leaf certificate that were issued, and that no CA /
// chain certificates leak into the keystore (matching the legacy SIA
// `openssl pkcs12 -export -inkey -in` behaviour).
func Test_writeKeypair_PKCS12(t *testing.T) {
	leafpk, leafPEM, d, store, meta := keystoreFixture(t)

	require.NoError(t, d.writeKeypair(meta, leafpk, leafPEM, nil))

	files, err := store.ReadFiles("vol-id")
	require.NoError(t, err)
	require.Contains(t, files, "service.pkcs12")

	gotKey, gotLeaf, caCerts, err := pkcs12.DecodeChain(files["service.pkcs12"], "changeit")
	require.NoError(t, err)
	require.Empty(t, caCerts, "PKCS12 should not contain CA / intermediate certs")

	gotECKey, ok := gotKey.(*ecdsa.PrivateKey)
	require.True(t, ok, "expected ECDSA private key")
	require.True(t, gotECKey.Equal(leafpk), "private key in PKCS12 must match the issued key")

	expectedLeaf := parseFirstCert(t, leafPEM)
	require.True(t, bytes.Equal(gotLeaf.Raw, expectedLeaf.Raw),
		"leaf certificate in PKCS12 must match the issued leaf")
}

// Test_writeKeypair_JKS verifies the JKS keystore contains exactly one
// PrivateKeyEntry under the configured alias, holding the same key and leaf
// certificate as the issued pair, and no extra CA / chain certs.
func Test_writeKeypair_JKS(t *testing.T) {
	leafpk, leafPEM, d, store, meta := keystoreFixture(t)

	require.NoError(t, d.writeKeypair(meta, leafpk, leafPEM, nil))

	files, err := store.ReadFiles("vol-id")
	require.NoError(t, err)
	require.Contains(t, files, "service.jks")

	ks := keystore.New()
	require.NoError(t, ks.Load(bytes.NewReader(files["service.jks"]), []byte("changeit")))

	aliases := ks.Aliases()
	require.Equal(t, []string{"service"}, aliases)

	entry, err := ks.GetPrivateKeyEntry("service", []byte("changeit"))
	require.NoError(t, err)
	require.Len(t, entry.CertificateChain, 1, "JKS chain should contain only the leaf")

	gotKey, err := x509.ParsePKCS8PrivateKey(entry.PrivateKey)
	require.NoError(t, err)
	gotECKey, ok := gotKey.(*ecdsa.PrivateKey)
	require.True(t, ok, "expected ECDSA private key")
	require.True(t, gotECKey.Equal(leafpk), "private key in JKS must match the issued key")

	expectedLeaf := parseFirstCert(t, leafPEM)
	require.True(t, bytes.Equal(entry.CertificateChain[0].Content, expectedLeaf.Raw),
		"leaf certificate in JKS must match the issued leaf")
}

// Test_writeKeypair_KeystoresDisabled ensures no keystore files are written
// when the master switch is off, even if filenames are configured. This is
// the default behaviour and guarantees the PEM-only on-disk layout is
// preserved when the feature is not opted into.
func Test_writeKeypair_KeystoresDisabled(t *testing.T) {
	leafpk, leafPEM, d, store, meta := keystoreFixture(t, func(d *Driver) {
		d.keystoreEnabled = false
		// Filenames stay populated to prove the master switch overrides them.
	})

	require.NoError(t, d.writeKeypair(meta, leafpk, leafPEM, nil))

	files, err := store.ReadFiles("vol-id")
	require.NoError(t, err)
	require.NotContains(t, files, "service.pkcs12")
	require.NotContains(t, files, "service.jks")
	require.Contains(t, files, "tls.crt")
	require.Contains(t, files, "tls.key")
}

// Test_writeKeypair_KeystoresEnabledSelectiveSkip ensures that with the
// master switch on, an individual keystore can still be skipped by setting
// its filename to the empty string.
func Test_writeKeypair_KeystoresEnabledSelectiveSkip(t *testing.T) {
	t.Run("only-pkcs12", func(t *testing.T) {
		leafpk, leafPEM, d, store, meta := keystoreFixture(t, func(d *Driver) {
			d.jksFileName = ""
		})
		require.NoError(t, d.writeKeypair(meta, leafpk, leafPEM, nil))
		files, err := store.ReadFiles("vol-id")
		require.NoError(t, err)
		require.Contains(t, files, "service.pkcs12")
		require.NotContains(t, files, "service.jks")
	})
	t.Run("only-jks", func(t *testing.T) {
		leafpk, leafPEM, d, store, meta := keystoreFixture(t, func(d *Driver) {
			d.keystoreFileName = ""
		})
		require.NoError(t, d.writeKeypair(meta, leafpk, leafPEM, nil))
		files, err := store.ReadFiles("vol-id")
		require.NoError(t, err)
		require.NotContains(t, files, "service.pkcs12")
		require.Contains(t, files, "service.jks")
	})
}

// Test_writeKeypair_KeystoresMatch cross-validates that the PKCS12 and JKS
// keystores written in the same refresh round expose identical key/cert
// material. This guards against any future divergence between the two
// encoders that could leave one stale relative to the other.
func Test_writeKeypair_KeystoresMatch(t *testing.T) {
	leafpk, leafPEM, d, store, meta := keystoreFixture(t)

	require.NoError(t, d.writeKeypair(meta, leafpk, leafPEM, nil))

	files, err := store.ReadFiles("vol-id")
	require.NoError(t, err)

	p12Key, p12Leaf, _, err := pkcs12.DecodeChain(files["service.pkcs12"], "changeit")
	require.NoError(t, err)

	ks := keystore.New()
	require.NoError(t, ks.Load(bytes.NewReader(files["service.jks"]), []byte("changeit")))
	jksEntry, err := ks.GetPrivateKeyEntry("service", []byte("changeit"))
	require.NoError(t, err)
	jksKey, err := x509.ParsePKCS8PrivateKey(jksEntry.PrivateKey)
	require.NoError(t, err)

	require.True(t, p12Key.(*ecdsa.PrivateKey).Equal(jksKey.(*ecdsa.PrivateKey)),
		"PKCS12 and JKS must wrap the same private key")
	require.True(t, bytes.Equal(p12Leaf.Raw, jksEntry.CertificateChain[0].Content),
		"PKCS12 and JKS must wrap the same leaf certificate")
}

func parseFirstCert(t *testing.T, pemBytes []byte) *x509.Certificate {
	t.Helper()
	certs, err := parseCertChain(pemBytes)
	require.NoError(t, err)
	require.NotEmpty(t, certs)
	return certs[0]
}

// Test_pickLeaf_ChainOrder ensures the leaf is selected by IsCA, not by chain
// order, so the keystore is robust to chains emitted in any order.
func Test_pickLeaf_ChainOrder(t *testing.T) {
	leaf := &x509.Certificate{IsCA: false}
	intermediate := &x509.Certificate{IsCA: true}
	root := &x509.Certificate{IsCA: true}

	cases := map[string][]*x509.Certificate{
		"leaf-first":             {leaf, intermediate, root},
		"intermediate-then-leaf": {intermediate, leaf, root},
		"leaf-last":              {root, intermediate, leaf},
		"leaf-only":              {leaf},
	}
	for name, chain := range cases {
		t.Run(name, func(t *testing.T) {
			require.Same(t, leaf, pickLeaf(chain))
		})
	}
}

// Test_pickLeaf_EdgeCases covers the empty input (returns nil) and the
// all-CA fallback path (returns the first cert as a safety net).
func Test_pickLeaf_EdgeCases(t *testing.T) {
	require.Nil(t, pickLeaf(nil))
	require.Nil(t, pickLeaf([]*x509.Certificate{}))

	first := &x509.Certificate{IsCA: true}
	second := &x509.Certificate{IsCA: true}
	require.Same(t, first, pickLeaf([]*x509.Certificate{first, second}),
		"with no non-CA cert, pickLeaf must fall back to the first cert")
}

// Test_writeKeypair_PicksLeafByIsCA verifies the end-to-end behaviour: when
// writeKeypair receives a PEM chain in [intermediate, leaf] order, both
// keystores still contain the leaf (not the intermediate).
func Test_writeKeypair_PicksLeafByIsCA(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	capk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	caTmpl, err := utilpki.CertificateTemplateFromCertificate(&cmapi.Certificate{
		Spec: cmapi.CertificateSpec{CommonName: "my-ca", IsCA: true},
	})
	require.NoError(t, err)
	caPEM, ca, err := utilpki.SignCertificate(caTmpl, caTmpl, capk.Public(), capk)
	require.NoError(t, err)

	leafpk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	leafTmpl, err := utilpki.CertificateTemplateFromCertificate(&cmapi.Certificate{
		Spec: cmapi.CertificateSpec{URIs: []string{"spiffe://athenz.io/ns/sandbox/sa/default"}},
	})
	require.NoError(t, err)
	leafPEM, _, err := utilpki.SignCertificate(leafTmpl, ca, leafpk.Public(), capk)
	require.NoError(t, err)

	// Build a chain in non-leaf-first order: [intermediate(=CA), leaf].
	swappedChain := append([]byte{}, caPEM...)
	swappedChain = append(swappedChain, leafPEM...)

	ch := make(chan []byte, 1)
	rootCAs := rootca.NewMemory(ctx, ch)
	ch <- caPEM
	store := storage.NewMemoryFS()
	d := &Driver{
		certFileName:     "tls.crt",
		keyFileName:      "tls.key",
		caFileName:       "ca.crt",
		keystoreEnabled:  true,
		keystoreFileName: "service.pkcs12",
		jksFileName:      "service.jks",
		keystorePassword: "changeit",
		keystoreAlias:    "service",
		rootCAs:          rootCAs,
		store:            store,
	}
	meta := metadata.Metadata{VolumeID: "vol-id"}
	_, err = store.RegisterMetadata(meta)
	require.NoError(t, err)

	require.NoError(t, d.writeKeypair(meta, leafpk, swappedChain, nil))

	files, err := store.ReadFiles("vol-id")
	require.NoError(t, err)

	expectedLeaf := parseFirstCert(t, leafPEM)

	_, p12Leaf, _, err := pkcs12.DecodeChain(files["service.pkcs12"], "changeit")
	require.NoError(t, err)
	require.True(t, bytes.Equal(p12Leaf.Raw, expectedLeaf.Raw),
		"PKCS12 must contain the leaf even when the chain is not leaf-first")

	ks := keystore.New()
	require.NoError(t, ks.Load(bytes.NewReader(files["service.jks"]), []byte("changeit")))
	jksEntry, err := ks.GetPrivateKeyEntry("service", []byte("changeit"))
	require.NoError(t, err)
	require.Len(t, jksEntry.CertificateChain, 1)
	require.True(t, bytes.Equal(jksEntry.CertificateChain[0].Content, expectedLeaf.Raw),
		"JKS must contain the leaf even when the chain is not leaf-first")
}

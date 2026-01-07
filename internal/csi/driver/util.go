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
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/cert-manager/csi-lib/metadata"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

const (
	AthenzDomainAnnotation = "athenz.io/domain"
)

// generatePrivateKey generates an ECDSA private key, which is the only currently supported type
func generatePrivateKey(_ metadata.Metadata) (crypto.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

// signRequest will sign a given X.509 certificate signing request with the given key.
func signRequest(_ metadata.Metadata, key crypto.PrivateKey, request *x509.CertificateRequest) ([]byte, error) {
	csrDer, err := x509.CreateCertificateRequest(rand.Reader, request, key)
	if err != nil {
		return nil, err
	}

	return pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrDer,
	}), nil
}

// extract domain and service from the service account name
// e.g. athenz.prod.api -> domain: athenz.prod, service: api
func extractDomainService(saName string) (string, string) {
	domain := ""
	service := ""
	if idx := strings.LastIndex(saName, "."); idx != -1 {
		domain = saName[:idx]
		service = saName[idx+1:]
	}
	return domain, service
}

func appendHostname(hostList []string, hostname string) []string {
	for _, host := range hostList {
		if host == hostname {
			return hostList
		}
	}
	return append(hostList, hostname)
}

func appendUri(uriList []*url.URL, uriValue string) []*url.URL {
	uri, err := url.Parse(uriValue)
	if err == nil {
		uriList = append(uriList, uri)
	}
	return uriList
}

func getNamespaceAnnotations(namespace string) (map[string]string, error) {
	config, err := rest.InClusterConfig()
	if err != nil {
		return nil, fmt.Errorf("non-standard SA fallabck: failed to get in cluster config: %w", err)
	}
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("non-standard SA fallabck: failed to get clientset: %w", err)
	}
	ns, err := clientset.CoreV1().Namespaces().Get(context.TODO(), namespace, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("non-standard SA fallabck: failed to get namespace: %w", err)
	}
	return ns.GetAnnotations(), nil
}

func getDomainFromNamespaceAnnotations(annotations map[string]string) string {
	if domain, ok := annotations[AthenzDomainAnnotation]; ok {
		return domain
	}
	return ""
}

// parseRefreshInterval parses a refresh interval string (e.g., "60m", "120m", "1h", "2h")
// and returns the duration. If the string is empty, it returns the default refresh interval with nil error.
// If invalid, it returns the default interval with an error describing the issue.
// Minimum allowed interval is 60 minutes.
func parseRefreshInterval(intervalStr string, defaultInterval time.Duration) (time.Duration, error) {
	if intervalStr == "" {
		return defaultInterval, fmt.Errorf("no refresh interval specified, using default %s", defaultInterval.String())
	}

	// Parse the duration value (e.g., "60m" -> 60 minutes, "1h" -> 1 hour)
	duration, err := time.ParseDuration(intervalStr)
	if err != nil {
		return defaultInterval, fmt.Errorf("failed to parse refresh interval %q: %w", intervalStr, err)
	}

	// Ensure the refresh interval is at least 60 minutes
	if duration < 60*time.Minute {
		return defaultInterval, fmt.Errorf("refresh interval %q is less than minimum 60 minutes", intervalStr)
	}

	return duration, nil
}

// calculateNextIssuanceTimeWithRefreshInterval returns the time when the certificate
// should be renewed based on the specified refresh interval from the current time.
func calculateNextIssuanceTimeWithRefreshInterval(refreshInterval time.Duration) time.Time {
	return time.Now().Add(refreshInterval)
}

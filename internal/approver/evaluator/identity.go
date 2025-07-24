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

package evaluator

import (
	"context"
	"crypto/x509"
	"fmt"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

const (
	AthenzDomainAnnotation = "athenz.io/domain"
)

// validateIdentity validates that the SPIFFE ID contained in the X.509
// certificate request matches that in the username.
// The username should be the Username as it appears on the CertificateRequest.
// This should be the ServiceAccount of the mounting Pod who has been
// impersonated to create the request.
func (i *internal) validateIdentity(csr *x509.CertificateRequest, username string) error {
	split := strings.Split(username, ":")
	if len(split) != 4 || split[0] != "system" || split[1] != "serviceaccount" {
		return fmt.Errorf("got non-serviceaccount encoded username: %q", username)
	}

	if csr.URIs[0].Scheme != "spiffe" {
		return fmt.Errorf("URI scheme is not spiffe: %s", csr.URIs[0].Scheme)
	}

	namespace := split[2]
	saName := split[3]
	expSpiffeID := fmt.Sprintf("spiffe://%s/ns/%s/sa/%s", i.trustDomain, namespace, saName)
	if csr.URIs[0].String() != expSpiffeID {
		// check fallback format for non-standard service account names
		annotations, err := getNamespaceAnnotations(namespace)
		if err != nil {
			return fmt.Errorf("validateIdentity in approver: failed to get namespace annotations for %s: %w", namespace, err)
		}
		domain := getDomainFromNamespaceAnnotations(annotations)
		expectedSAComponent := fmt.Sprintf("%s.%s", domain, saName)
		expSpiffeID = fmt.Sprintf("spiffe://%s/ns/%s/sa/%s", i.trustDomain, namespace, expectedSAComponent)
		if csr.URIs[0].String() != expSpiffeID {
			return fmt.Errorf("unexpected SPIFFE ID requested, exp=%q got=%q", expSpiffeID, csr.URIs[0].String())
		}
	}

	if i.multiTenancy {
		err := validateIdentityDomain(namespace, saName)
		if err != nil {
			return err
		}
	}

	return nil
}

func validateIdentityDomain(namespace, serviceAccount string) error {
	dashedDomain := getDashedDomain(getDomainFromServiceAccount(serviceAccount))
	if namespace != dashedDomain {
		annotations, err := getNamespaceAnnotations(namespace)
		if err != nil {
			return fmt.Errorf("validateIdentity in approver: failed to get namespace annotations for %s: %w", namespace, err)
		}
		if annotations == nil || annotations[AthenzDomainAnnotation] == "" {
			return fmt.Errorf("validateIdentity in approver: namespace %s does not have the %s annotation", namespace, AthenzDomainAnnotation)
		}
		domain := getDomainFromServiceAccount(serviceAccount)
		if annotations[AthenzDomainAnnotation] != domain {
			// check fallback format for non-standard service account names
			domainFromNS := getDomainFromNamespaceAnnotations(annotations)
			dashedNSDomain := getDashedDomain(domainFromNS)
			if namespace != dashedNSDomain {
				return fmt.Errorf("domain %s or namespace annotation value %s do not match with namespace name %s", domain, annotations[AthenzDomainAnnotation], namespace)
			}

		}
	}
	return nil
}

// extract domain from the service account name and convert it to dashed format
// . becomes - and - becomes --
// e.g. athenz.prod.api -> athenz-prod
// e.g. athenz.aws-prod.api -> athenz-aws--prod
func getDomainFromServiceAccount(saName string) string {
	domain := saName
	if idx := strings.LastIndex(saName, "."); idx != -1 {
		domain = saName[:idx]
	}
	return domain
}

func getDashedDomain(domain string) string {
	domain = strings.ReplaceAll(domain, "-", "--")
	domain = strings.ReplaceAll(domain, ".", "-")
	return domain
}

func getNamespaceAnnotations(namespace string) (map[string]string, error) {
	config, err := rest.InClusterConfig()
	if err != nil {
		return nil, fmt.Errorf("validateIdentity in approver: failed to get in cluster config: %w", err)
	}
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("validateIdentity in approver: failed to get clientset: %w", err)
	}
	ns, err := clientset.CoreV1().Namespaces().Get(context.TODO(), namespace, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("validateIdentity in approver: failed to get namespace: %w", err)
	}
	return ns.GetAnnotations(), nil
}

func getDomainFromNamespaceAnnotations(annotations map[string]string) string {
	if domain, ok := annotations[AthenzDomainAnnotation]; ok {
		return domain
	}
	return ""
}

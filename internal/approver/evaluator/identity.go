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

	if len(csr.URIs) == 0 {
		return fmt.Errorf("request contains no URI SANs")
	}

	if csr.URIs[0].Scheme != "spiffe" {
		return fmt.Errorf("URI scheme is not spiffe: %s", csr.URIs[0].Scheme)
	}

	namespace := split[2]
	saName := split[3]

	// saComponent is the sa segment of the requested SPIFFE ID; the issuer derives the
	// Athenz domain and service from it.
	saComponent := saName
	expSpiffeID := fmt.Sprintf("spiffe://%s/ns/%s/sa/%s", i.trustDomain, namespace, saName)
	if csr.URIs[0].String() != expSpiffeID {
		// check fallback format for non-standard service account names, where the domain
		// comes from the namespace: spiffe://<td>/ns/<ns>/sa/<domain>.<sa>
		domain, err := i.getNamespaceDomain(namespace)
		if err != nil {
			return err
		}
		if domain == "" {
			return fmt.Errorf("unexpected SPIFFE ID requested, exp=%q got=%q", expSpiffeID, csr.URIs[0].String())
		}
		saComponent = fmt.Sprintf("%s.%s", domain, saName)
		expSpiffeID = fmt.Sprintf("spiffe://%s/ns/%s/sa/%s", i.trustDomain, namespace, saComponent)
		if csr.URIs[0].String() != expSpiffeID {
			return fmt.Errorf("unexpected SPIFFE ID requested, exp=%q got=%q", expSpiffeID, csr.URIs[0].String())
		}
	}

	if i.multiTenancy {
		if err := i.validateIdentityDomain(namespace, saComponent); err != nil {
			return err
		}
	}

	return nil
}

// validateIdentityDomain verifies that the namespace may hold identities of the Athenz
// domain named by saComponent ({domain}.{service}). A namespace whose name is the dashed
// form of the domain passes without an API call. Otherwise the namespace's athenz.io/domain
// annotation, else its athenz.io/domain label, must equal the domain; only cluster admins
// can edit a Namespace. athenz-issuer applies the same rule before it requests a
// ServiceAccount token.
func (i *internal) validateIdentityDomain(namespace, saComponent string) error {
	idx := strings.LastIndex(saComponent, ".")
	if idx <= 0 || idx == len(saComponent)-1 {
		return fmt.Errorf("validateIdentity in approver: service account %q does not name an Athenz {domain}.{service}", saComponent)
	}
	domain := saComponent[:idx]
	if namespace == getDashedDomain(domain) {
		return nil
	}

	nsDomain, err := i.getNamespaceDomain(namespace)
	if err != nil {
		return err
	}
	if nsDomain == "" {
		return fmt.Errorf("validateIdentity in approver: domain %s does not match namespace %s, which has no %s annotation or label",
			domain, namespace, AthenzDomainAnnotation)
	}
	if nsDomain != domain {
		return fmt.Errorf("validateIdentity in approver: domain %s does not match namespace %s domain %s (%s annotation or label)",
			domain, namespace, nsDomain, AthenzDomainAnnotation)
	}
	return nil
}

// getDashedDomain converts a domain to its namespace form: "-" becomes "--" and "." becomes "-"
// e.g. athenz.aws-prod -> athenz-aws--prod
func getDashedDomain(domain string) string {
	domain = strings.ReplaceAll(domain, "-", "--")
	domain = strings.ReplaceAll(domain, ".", "-")
	return domain
}

// getNamespaceDomain returns the namespace's Athenz domain: its athenz.io/domain annotation,
// else its athenz.io/domain label, else "". It uses the injected client when one was
// configured and an in-cluster client otherwise.
func (i *internal) getNamespaceDomain(namespace string) (string, error) {
	client := i.kubeClient
	if client == nil {
		config, err := rest.InClusterConfig()
		if err != nil {
			return "", fmt.Errorf("validateIdentity in approver: failed to get in cluster config: %w", err)
		}
		client, err = kubernetes.NewForConfig(config)
		if err != nil {
			return "", fmt.Errorf("validateIdentity in approver: failed to get clientset: %w", err)
		}
	}
	ns, err := client.CoreV1().Namespaces().Get(context.TODO(), namespace, metav1.GetOptions{})
	if err != nil {
		return "", fmt.Errorf("validateIdentity in approver: failed to get namespace %s: %w", namespace, err)
	}
	if domain := ns.GetAnnotations()[AthenzDomainAnnotation]; domain != "" {
		return domain, nil
	}
	return ns.GetLabels()[AthenzDomainAnnotation], nil
}

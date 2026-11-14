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
	"crypto/x509"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
)

// ns builds a Namespace, annotated with athenz.io/domain when domain is not empty.
func ns(name, domain string) *corev1.Namespace {
	return nsWith(name, domain, "")
}

// nsWith builds a Namespace with an optional athenz.io/domain annotation and label.
func nsWith(name, annotation, label string) *corev1.Namespace {
	n := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: name}}
	if annotation != "" {
		n.Annotations = map[string]string{AthenzDomainAnnotation: annotation}
	}
	if label != "" {
		n.Labels = map[string]string{AthenzDomainAnnotation: label}
	}
	return n
}

func Test_validateIdentity(t *testing.T) {
	tests := map[string]struct {
		uris         []string
		username     string
		expErr       bool
		multiTenancy bool
		namespaces   []*corev1.Namespace
	}{
		"if username is malformed, expect error": {
			uris:         []string{"spiffe://foo.bar/ns/sandbox/sa/sleep"},
			username:     "system:serviceaccount:foo",
			expErr:       true,
			multiTenancy: false,
		},
		"if no URIs defined, expect error": {
			uris:         nil,
			username:     "system:serviceaccount:sandbox:sandbox.sleep",
			expErr:       true,
			multiTenancy: false,
		},
		"if multiple URIs defined, don't expect error": {
			uris: []string{
				"spiffe://foo.bar/ns/sandbox/sa/sandbox.sleep",
				"athenz://foo.bar/instanceid/provider/1234",
			},
			username:     "system:serviceaccount:sandbox:sandbox.sleep",
			expErr:       false,
			multiTenancy: false,
		},
		"if URI is not using SPIFFE, expect error": {
			uris:         []string{"http://foo.bar/ns/sandbox/sa/sleep"},
			username:     "system:serviceaccount:sandbox:sleep",
			expErr:       true,
			multiTenancy: false,
		},
		"if trust domain is wrong, expect error": {
			uris:         []string{"spiffe://bar.foo/ns/sandbox/sa/sleep"},
			username:     "system:serviceaccount:sandbox:sleep",
			expErr:       true,
			multiTenancy: false,
		},
		"if SPIFFE ID doesn't match the username, expect error": {
			uris:         []string{"spiffe://foo.bar/ns/sandbox/sa/httpbin"},
			username:     "system:serviceaccount:sandbox:sleep",
			expErr:       true,
			multiTenancy: false,
		},
		"if SPIFFE ID matches username, don't expect error": {
			uris:         []string{"spiffe://foo.bar/ns/sandbox-prod/sa/sandbox.prod.sleep"},
			username:     "system:serviceaccount:sandbox-prod:sandbox.prod.sleep",
			expErr:       false,
			multiTenancy: false,
		},
		"if domain and namespace don't match, expect error": {
			uris:         []string{"spiffe://foo.bar/ns/sandbox/sa/sleep"},
			username:     "system:serviceaccount:sandbox:sleep",
			expErr:       true,
			multiTenancy: true,
		},
		"if namespace matches domain, don't expect error (no namespace lookup needed)": {
			uris:         []string{"spiffe://foo.bar/ns/sandbox--bin-prod/sa/sandbox-bin.prod.sleep"},
			username:     "system:serviceaccount:sandbox--bin-prod:sandbox-bin.prod.sleep",
			expErr:       false,
			multiTenancy: true,
		},
		"multi-tenancy: SA of another domain in an annotated namespace, expect error": {
			uris:         []string{"spiffe://foo.bar/ns/tenant-a/sa/other.svc"},
			username:     "system:serviceaccount:tenant-a:other.svc",
			expErr:       true,
			multiTenancy: true,
			namespaces:   []*corev1.Namespace{ns("tenant-a", "tenant.a")},
		},
		"multi-tenancy: SA of another domain in an unannotated namespace, expect error": {
			uris:         []string{"spiffe://foo.bar/ns/tenant-a/sa/other.svc"},
			username:     "system:serviceaccount:tenant-a:other.svc",
			expErr:       true,
			multiTenancy: true,
			namespaces:   []*corev1.Namespace{ns("tenant-a", "")},
		},
		"multi-tenancy: SA of the annotated domain, don't expect error": {
			uris:         []string{"spiffe://foo.bar/ns/finance-k8s/sa/finance.k8s.api"},
			username:     "system:serviceaccount:finance-k8s:finance.k8s.api",
			expErr:       false,
			multiTenancy: true,
			namespaces:   []*corev1.Namespace{ns("finance-k8s", "finance.k8s")},
		},
		"multi-tenancy: second namespace annotated with the same domain, don't expect error": {
			uris:         []string{"spiffe://foo.bar/ns/payments-batch/sa/payments.prod.worker"},
			username:     "system:serviceaccount:payments-batch:payments.prod.worker",
			expErr:       false,
			multiTenancy: true,
			namespaces:   []*corev1.Namespace{ns("payments-batch", "payments.prod")},
		},
		"multi-tenancy: unrelated namespace name annotated with the domain, don't expect error": {
			uris:         []string{"spiffe://foo.bar/ns/team-x-tools/sa/payments.prod.cli"},
			username:     "system:serviceaccount:team-x-tools:payments.prod.cli",
			expErr:       false,
			multiTenancy: true,
			namespaces:   []*corev1.Namespace{ns("team-x-tools", "payments.prod")},
		},
		"multi-tenancy: label only, SA of the labeled domain, don't expect error": {
			uris:         []string{"spiffe://foo.bar/ns/omega-monitoring/sa/omega.team.prom"},
			username:     "system:serviceaccount:omega-monitoring:omega.team.prom",
			expErr:       false,
			multiTenancy: true,
			namespaces:   []*corev1.Namespace{nsWith("omega-monitoring", "", "omega.team")},
		},
		"multi-tenancy: label only, SA of another domain, expect error": {
			uris:         []string{"spiffe://foo.bar/ns/omega-monitoring/sa/other.svc"},
			username:     "system:serviceaccount:omega-monitoring:other.svc",
			expErr:       true,
			multiTenancy: true,
			namespaces:   []*corev1.Namespace{nsWith("omega-monitoring", "", "omega.team")},
		},
		"multi-tenancy: annotation wins over label, expect error for the label's domain": {
			uris:         []string{"spiffe://foo.bar/ns/ns-a/sa/omega.team.prom"},
			username:     "system:serviceaccount:ns-a:omega.team.prom",
			expErr:       true,
			multiTenancy: true,
			namespaces:   []*corev1.Namespace{nsWith("ns-a", "payments.prod", "omega.team")},
		},
		"non-dotted SA with domain from namespace label, don't expect error": {
			uris:         []string{"spiffe://foo.bar/ns/omega-monitoring/sa/omega.team.prom"},
			username:     "system:serviceaccount:omega-monitoring:prom",
			expErr:       false,
			multiTenancy: true,
			namespaces:   []*corev1.Namespace{nsWith("omega-monitoring", "", "omega.team")},
		},
		"multi-tenancy: name match passes even when annotated with another domain, don't expect error": {
			uris:         []string{"spiffe://foo.bar/ns/app-backend/sa/app.backend.api"},
			username:     "system:serviceaccount:app-backend:app.backend.api",
			expErr:       false,
			multiTenancy: true,
			namespaces:   []*corev1.Namespace{ns("app-backend", "other.domain")},
		},
		"multi-tenancy: annotated platform namespace (ambient ztunnel), don't expect error": {
			uris:         []string{"spiffe://foo.bar/ns/istio-system/sa/example.k8s.ztunnel"},
			username:     "system:serviceaccount:istio-system:example.k8s.ztunnel",
			expErr:       false,
			multiTenancy: true,
			namespaces:   []*corev1.Namespace{ns("istio-system", "example.k8s")},
		},
		"multi-tenancy: non-dotted SA with domain from namespace annotation, don't expect error": {
			uris:         []string{"spiffe://foo.bar/ns/finance-k8s/sa/finance.k8s.api"},
			username:     "system:serviceaccount:finance-k8s:api",
			expErr:       false,
			multiTenancy: true,
			namespaces:   []*corev1.Namespace{ns("finance-k8s", "finance.k8s")},
		},
		"non-dotted SA with domain from namespace annotation, don't expect error": {
			uris:         []string{"spiffe://foo.bar/ns/my-ns/sa/finance.k8s.api"},
			username:     "system:serviceaccount:my-ns:api",
			expErr:       false,
			multiTenancy: false,
			namespaces:   []*corev1.Namespace{ns("my-ns", "finance.k8s")},
		},
		"non-dotted SA naming a domain the namespace annotation does not, expect error": {
			uris:         []string{"spiffe://foo.bar/ns/my-ns/sa/other.api"},
			username:     "system:serviceaccount:my-ns:api",
			expErr:       true,
			multiTenancy: false,
			namespaces:   []*corev1.Namespace{ns("my-ns", "finance.k8s")},
		},
		"non-dotted SA fallback without a namespace annotation, expect error": {
			uris:         []string{"spiffe://foo.bar/ns/my-ns/sa/.api"},
			username:     "system:serviceaccount:my-ns:api",
			expErr:       true,
			multiTenancy: false,
			namespaces:   []*corev1.Namespace{ns("my-ns", "")},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			objs := make([]runtime.Object, len(test.namespaces))
			for n, namespace := range test.namespaces {
				objs[n] = namespace
			}
			i := &internal{
				trustDomain:  "foo.bar",
				multiTenancy: test.multiTenancy,
				kubeClient:   fake.NewClientset(objs...),
			}

			var uris []*url.URL
			for _, uriStr := range test.uris {
				uri, err := url.Parse(uriStr)
				assert.NoError(t, err)
				uris = append(uris, uri)
			}

			err := i.validateIdentity(&x509.CertificateRequest{URIs: uris}, test.username)
			assert.Equalf(t, test.expErr, err != nil, "%v", err)
		})
	}
}

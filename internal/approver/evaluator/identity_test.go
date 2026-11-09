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

func Test_validateIdentity(t *testing.T) {
	// Namespace lookups must go through the injected client, never in-cluster config.
	t.Setenv("KUBERNETES_SERVICE_HOST", "")
	t.Setenv("KUBERNETES_SERVICE_PORT", "")

	namespaces := []*corev1.Namespace{
		{ObjectMeta: metav1.ObjectMeta{
			Name:        "sandbox",
			Annotations: map[string]string{AthenzDomainAnnotation: "sandbox.prod"},
		}},
		{ObjectMeta: metav1.ObjectMeta{
			Name:        "custom-ns",
			Annotations: map[string]string{AthenzDomainAnnotation: "sandbox.prod"},
		}},
		{ObjectMeta: metav1.ObjectMeta{Name: "no-annotation"}},
	}

	tests := map[string]struct {
		uris            []string
		username        string
		expErr          bool
		multiTenancy    bool
		expNamespaceGet bool
	}{
		"if username is malformed, expect error": {
			uris:         []string{"spiffe://foo.bar/ns/sandbox/sa/sleep"},
			username:     "system:serviceaccount:foo",
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
			uris:            []string{"spiffe://bar.foo/ns/sandbox/sa/sleep"},
			username:        "system:serviceaccount:sandbox:sleep",
			expErr:          true,
			multiTenancy:    false,
			expNamespaceGet: true,
		},
		"if SPIFFE ID doesn't match the username, expect error": {
			uris:            []string{"spiffe://foo.bar/ns/sandbox/sa/httpbin"},
			username:        "system:serviceaccount:sandbox:sleep",
			expErr:          true,
			multiTenancy:    false,
			expNamespaceGet: true,
		},
		"if SPIFFE ID matches the namespace domain annotation fallback, don't expect error": {
			uris:            []string{"spiffe://foo.bar/ns/sandbox/sa/sandbox.prod.sleep"},
			username:        "system:serviceaccount:sandbox:sleep",
			expErr:          false,
			multiTenancy:    false,
			expNamespaceGet: true,
		},
		"if namespace for the fallback lookup does not exist, expect error": {
			uris:            []string{"spiffe://foo.bar/ns/missing/sa/sandbox.prod.sleep"},
			username:        "system:serviceaccount:missing:sleep",
			expErr:          true,
			multiTenancy:    false,
			expNamespaceGet: true,
		},
		"if SPIFFE ID matches username, don't expect error": {
			uris:         []string{"spiffe://foo.bar/ns/sandbox-prod/sa/sandbox.prod.sleep"},
			username:     "system:serviceaccount:sandbox-prod:sandbox.prod.sleep",
			expErr:       false,
			multiTenancy: false,
		},
		"if domain and namespace don't match, expect error": {
			uris:            []string{"spiffe://foo.bar/ns/sandbox/sa/sleep"},
			username:        "system:serviceaccount:sandbox:sleep",
			expErr:          true,
			multiTenancy:    true,
			expNamespaceGet: true,
		},
		"if namespace annotation matches the domain, don't expect error": {
			uris:            []string{"spiffe://foo.bar/ns/custom-ns/sa/sandbox.prod.sleep"},
			username:        "system:serviceaccount:custom-ns:sandbox.prod.sleep",
			expErr:          false,
			multiTenancy:    true,
			expNamespaceGet: true,
		},
		"if namespace has no domain annotation, expect error": {
			uris:            []string{"spiffe://foo.bar/ns/no-annotation/sa/sandbox.prod.sleep"},
			username:        "system:serviceaccount:no-annotation:sandbox.prod.sleep",
			expErr:          true,
			multiTenancy:    true,
			expNamespaceGet: true,
		},
		"if namespace matches domain, don't expect error": {
			uris:         []string{"spiffe://foo.bar/ns/sandbox--bin-prod/sa/sandbox-bin.prod.sleep"},
			username:     "system:serviceaccount:sandbox--bin-prod:sandbox-bin.prod.sleep",
			expErr:       false,
			multiTenancy: true,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			var objs []runtime.Object
			for _, ns := range namespaces {
				objs = append(objs, ns.DeepCopy())
			}
			kubeClient := fake.NewClientset(objs...)
			i := &internal{
				trustDomain:  "foo.bar",
				multiTenancy: test.multiTenancy,
				kubeClient:   kubeClient,
			}

			var uris []*url.URL
			for _, uriStr := range test.uris {
				uri, err := url.Parse(uriStr)
				assert.NoError(t, err)
				uris = append(uris, uri)
			}

			err := i.validateIdentity(&x509.CertificateRequest{URIs: uris}, test.username)
			assert.Equalf(t, test.expErr, err != nil, "%v", err)

			var gotNamespaceGet bool
			for _, action := range kubeClient.Actions() {
				if action.Matches("get", "namespaces") {
					gotNamespaceGet = true
				}
			}
			assert.Equal(t, test.expNamespaceGet, gotNamespaceGet)
		})
	}
}

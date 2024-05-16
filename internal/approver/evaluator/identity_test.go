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
)

func Test_validateIdentity(t *testing.T) {
	tests := map[string]struct {
		uris     			[]string
		username 			string
		expErr   			bool
		multiTenancy 	bool
	}{
		"if username is malformed, expect error": {
			uris:     []string{"spiffe://foo.bar/ns/sandbox/sa/sleep"},
			username: "system:serviceaccount:foo",
			expErr:   true,
			multiTenancy: false,
		},
		"if multiple URIs defined, don't expect error": {
			uris: []string{
				"spiffe://foo.bar/ns/sandbox/sa/sandbox.sleep",
				"athenz://foo.bar/instanceid/provider/1234",
			},
			username: "system:serviceaccount:sandbox:sandbox.sleep",
			expErr:   false,
			multiTenancy: false,
		},
		"if URI is not using SPIFFE, expect error": {
			uris:     []string{"http://foo.bar/ns/sandbox/sa/sleep"},
			username: "system:serviceaccount:sandbox:sleep",
			expErr:   true,
			multiTenancy: false,
		},
		"if trust domain is wrong, expect error": {
			uris:     []string{"spiffe://bar.foo/ns/sandbox/sa/sleep"},
			username: "system:serviceaccount:sandbox:sleep",
			expErr:   true,
			multiTenancy: false,
		},
		"if SPIFFE ID doesn't match the username, expect error": {
			uris:     []string{"spiffe://foo.bar/ns/sandbox/sa/httpbin"},
			username: "system:serviceaccount:sandbox:sleep",
			expErr:   true,
			multiTenancy: false,
		},
		"if SPIFFE ID matches username, don't expect error": {
			uris:     []string{"spiffe://foo.bar/ns/sandbox-prod/sa/sandbox.prod.sleep"},
			username: "system:serviceaccount:sandbox-prod:sandbox.prod.sleep",
			expErr:   false,
			multiTenancy: false,
		},
		"if domain and namespace don't match, expect error": {
			uris:     []string{"spiffe://foo.bar/ns/sandbox/sa/sleep"},
			username: "system:serviceaccount:sandbox:sleep",
			expErr:   true,
			multiTenancy: true,
		},
		"if namespace matches domain, don't expect error": {
			uris:     []string{"spiffe://foo.bar/ns/sandbox--bin-prod/sa/sandbox-bin.prod.sleep"},
			username: "system:serviceaccount:sandbox--bin-prod:sandbox-bin.prod.sleep",
			expErr:   false,
			multiTenancy: true,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			i := &internal{
				trustDomain: "foo.bar",
				multiTenancy: test.multiTenancy,
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

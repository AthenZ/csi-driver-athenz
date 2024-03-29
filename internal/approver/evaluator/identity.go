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
	"fmt"
	"strings"
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

	expSpiffeID := fmt.Sprintf("spiffe://%s/ns/%s/sa/%s", i.trustDomain, split[2], split[3])
	if csr.URIs[0].String() != expSpiffeID {
		return fmt.Errorf("unexpected SPIFFE ID requested, exp=%q got=%q", expSpiffeID, csr.URIs[0].String())
	}

	return nil
}

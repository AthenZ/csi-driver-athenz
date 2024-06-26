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
	"fmt"
	"time"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	"github.com/cert-manager/cert-manager/pkg/util"
	utilpki "github.com/cert-manager/cert-manager/pkg/util/pki"
)

var (
	requiredUsages = []cmapi.KeyUsage{
		cmapi.UsageKeyEncipherment,
		cmapi.UsageDigitalSignature,
		cmapi.UsageClientAuth,
		cmapi.UsageServerAuth,
	}
)

// Interface is the Evaluator which is used for determining whether a
// CertificateRequest should be approved or denied.
type Interface interface {
	Evaluate(*cmapi.CertificateRequest) error
}

// Options is the options to configure the evaluator.
type Options struct {
	// TrustDomain is the trust domain that will be asserted when evaluating
	// CertificateRequests URI SANs.
	TrustDomain string

	// CertificateRequestDuration is the duration that users _must_ request for,
	// else the request will be denied.
	CertificateRequestDuration time.Duration

	// Multi-tenancy is the flag to enable strict multi-tenancy support where
	// namespace name has to match with the domain name.
	MultiTenancy bool
}

// internal is the internal implementation of the evaluator that should be used
// when running the approver controller.
type internal struct {
	// trustDomain is the trust domain that will be asserted when evaluating
	// CertificateRequests URI SANs.
	trustDomain string

	// certificateRequestDuration is the duration that users _must_ request for,
	// else the request will be denied.
	certificateRequestDuration time.Duration

	// Multi-tenancy is the flag to enable strict multi-tenancy support where
	// namespace name has to match with the domain name.
	multiTenancy bool
}

// New constructs a new evaluator.
func New(opts Options) Interface {
	return &internal{
		trustDomain:                opts.TrustDomain,
		certificateRequestDuration: opts.CertificateRequestDuration,
		multiTenancy:               opts.MultiTenancy,
	}
}

// Evaluate evaluates whether a CertificateRequest should be approved or
// denied. A CertificateRequest should be denied if this function returns an
// error, should be approved otherwise.
func (i *internal) Evaluate(req *cmapi.CertificateRequest) error {
	csr, err := utilpki.DecodeX509CertificateRequestBytes(req.Spec.Request)
	if err != nil {
		return fmt.Errorf("failed to parse request: %w", err)
	}

	if req.Spec.Duration == nil || req.Spec.Duration.Duration != i.certificateRequestDuration {
		return fmt.Errorf("requested certificate doesn't match required, required=%q got=%v",
			i.certificateRequestDuration.String(), req.Spec.Duration)
	}

	if err := csr.CheckSignature(); err != nil {
		return fmt.Errorf("signature check failed for csr: %w", err)
	}

	if err := validateCSRExtensions(csr); err != nil {
		return err
	}

	if req.Spec.IsCA {
		return fmt.Errorf("request contains spec.isCA=true")
	}

	if !util.EqualKeyUsagesUnsorted(req.Spec.Usages, requiredUsages) {
		return fmt.Errorf("request contains wrong usages, exp=%v got=%v", requiredUsages, req.Spec.Usages)
	}

	if err := i.validateIdentity(csr, req.Spec.Username); err != nil {
		return err
	}

	return nil
}

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

package test

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"

	apiutil "github.com/cert-manager/cert-manager/pkg/api/util"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/klog/v2/klogr"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/config"
	"sigs.k8s.io/controller-runtime/pkg/metrics/server"

	"github.com/AthenZ/csi-driver-athenz/internal/approver/controller"
	evaluatorfake "github.com/AthenZ/csi-driver-athenz/internal/approver/evaluator/fake"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Context("Approval", func() {
	var (
		ctx    context.Context
		cancel func()

		cl        client.Client
		namespace corev1.Namespace

		maxConcurrent int

		evaluator = evaluatorfake.New()
		issuerRef = cmmeta.IssuerReference{
			Name:  "athenz-ca",
			Kind:  "ClusterIssuer",
			Group: "cert-manager.io",
		}
	)

	BeforeEach(func() {
		maxConcurrent = 0
	})

	JustBeforeEach(func() {
		ctx, cancel = context.WithCancel(context.TODO())

		scheme := runtime.NewScheme()
		Expect(corev1.AddToScheme(scheme)).NotTo(HaveOccurred())
		Expect(cmapi.AddToScheme(scheme)).NotTo(HaveOccurred())

		var err error
		cl, err = client.New(env.Config, client.Options{Scheme: scheme})
		Expect(err).NotTo(HaveOccurred())

		namespace = corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "test-csi-driver-athenz-",
			},
		}
		Expect(cl.Create(ctx, &namespace)).NotTo(HaveOccurred())

		log := klogr.New().WithName("testing")
		mgr, err := ctrl.NewManager(env.Config, ctrl.Options{
			Scheme:         scheme,
			LeaderElection: true,
			Metrics: server.Options{
				BindAddress: "0",
			},
			LeaderElectionNamespace:       namespace.Name,
			LeaderElectionID:              "csi-driver-athenz-approver",
			LeaderElectionReleaseOnCancel: true,
			Logger:                        log,
			Controller: config.Controller{
				// need to skip unique controller name validation
				// since all tests need a dedicated controller
				SkipNameValidation: ptr.To(true),
			},
		})
		Expect(err).NotTo(HaveOccurred())

		Expect(controller.AddApprover(ctx, log, controller.Options{
			Manager:                 mgr,
			Evaluator:               evaluator,
			IssuerRef:               issuerRef,
			MaxConcurrentReconciles: maxConcurrent,
		})).NotTo(HaveOccurred())

		By("Running Approver controller")
		go mgr.Start(ctx)

		By("Waiting for Leader Election")
		<-mgr.Elected()

		By("Waiting for Informers to Sync")
		Expect(mgr.GetCache().WaitForCacheSync(ctx)).Should(BeTrue())
	})

	JustAfterEach(func() {
		Expect(cl.Delete(ctx, &namespace)).NotTo(HaveOccurred())
		cancel()
	})

	It("should ignore CertificateRequest that have the wrong IssuerRef", func() {
		cr := cmapi.CertificateRequest{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "csi-driver-athenz-",
				Namespace:    namespace.Name,
			},
			Spec: cmapi.CertificateRequestSpec{
				Request: []byte("request"),
				IssuerRef: cmmeta.IssuerReference{
					Name:  "not-athenz-ca",
					Kind:  "ClusterIssuer",
					Group: "cert-manager.io",
				},
			},
		}
		Expect(cl.Create(ctx, &cr)).NotTo(HaveOccurred())

		Consistently(func() bool {
			Eventually(func() error {
				return cl.Get(ctx, client.ObjectKeyFromObject(&cr), &cr)
			}).Should(BeNil())
			return apiutil.CertificateRequestIsApproved(&cr) || apiutil.CertificateRequestIsDenied(&cr)
		}, "3s").Should(BeFalse(), "expected neither approved not denied")
	})

	It("should deny CertificateRequest when the evaluator returns error", func() {
		evaluator.WithEvaluate(func(_ *cmapi.CertificateRequest) error {
			return errors.New("this is an error")
		})

		cr := cmapi.CertificateRequest{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "csi-driver-athenz-",
				Namespace:    namespace.Name,
			},
			Spec: cmapi.CertificateRequestSpec{
				Request:   []byte("request"),
				IssuerRef: issuerRef,
			},
		}
		Expect(cl.Create(ctx, &cr)).NotTo(HaveOccurred())

		Eventually(func() bool {
			Eventually(func() error {
				return cl.Get(ctx, client.ObjectKeyFromObject(&cr), &cr)
			}).Should(BeNil())
			return apiutil.CertificateRequestIsDenied(&cr)
		}).Should(BeTrue(), "expected denial")
	})

	It("should approve CertificateRequest when the evaluator returns nil", func() {
		evaluator.WithEvaluate(func(_ *cmapi.CertificateRequest) error {
			return nil
		})

		cr := cmapi.CertificateRequest{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "csi-driver-athenz-",
				Namespace:    namespace.Name,
			},
			Spec: cmapi.CertificateRequestSpec{
				Request:   []byte("request"),
				IssuerRef: issuerRef,
			},
		}
		Expect(cl.Create(ctx, &cr)).NotTo(HaveOccurred())

		Eventually(func() bool {
			Eventually(func() error {
				return cl.Get(ctx, client.ObjectKeyFromObject(&cr), &cr)
			}).Should(BeNil())
			return apiutil.CertificateRequestIsApproved(&cr)
		}).Should(BeTrue(), "expected approval")
	})

	for _, tc := range []struct {
		limit    int
		requests int
	}{
		{limit: 1, requests: 3},
		{limit: 2, requests: 5},
		{limit: 3, requests: 3},
	} {
		Context(fmt.Sprintf("with MaxConcurrentReconciles=%d", tc.limit), func() {
			BeforeEach(func() {
				maxConcurrent = tc.limit
			})

			It("should evaluate requests in parallel up to the limit and no further", func() {
				var inFlight, peak atomic.Int32
				gate := make(chan struct{})
				var once sync.Once
				releaseAll := func() { once.Do(func() { close(gate) }) }
				DeferCleanup(releaseAll)

				evaluator.WithEvaluate(func(_ *cmapi.CertificateRequest) error {
					n := inFlight.Add(1)
					for {
						p := peak.Load()
						if n <= p || peak.CompareAndSwap(p, n) {
							break
						}
					}
					<-gate
					inFlight.Add(-1)
					return nil
				})

				crs := make([]*cmapi.CertificateRequest, tc.requests)
				for i := range crs {
					crs[i] = &cmapi.CertificateRequest{
						ObjectMeta: metav1.ObjectMeta{
							GenerateName: "csi-driver-athenz-",
							Namespace:    namespace.Name,
						},
						Spec: cmapi.CertificateRequestSpec{
							Request:   []byte("request"),
							IssuerRef: issuerRef,
						},
					}
					Expect(cl.Create(ctx, crs[i])).NotTo(HaveOccurred())
				}

				want := int32(min(tc.limit, tc.requests))
				Eventually(inFlight.Load, "10s").Should(Equal(want), "expected evaluations to reach the limit")
				Consistently(peak.Load, "2s").Should(Equal(want), "expected evaluations to stay at the limit")

				releaseAll()
				for _, cr := range crs {
					Eventually(func() bool {
						if err := cl.Get(ctx, client.ObjectKeyFromObject(cr), cr); err != nil {
							return false
						}
						return apiutil.CertificateRequestIsApproved(cr)
					}, "10s").Should(BeTrue(), "expected approval")
				}
				Expect(peak.Load()).To(Equal(want))
			})
		})
	}
})

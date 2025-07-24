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

package namespacedomain

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os/exec"
	"time"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/pointer"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/AthenZ/csi-driver-athenz/test/e2e/framework"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = framework.CasesDescribe("NamespaceDomain", func() {
	f := framework.NewDefaultFramework("NamespaceDomain")

	var (
		serviceAccount corev1.ServiceAccount
		namespace      corev1.Namespace
		cl             client.Client
		role           rbacv1.Role
		rolebinding    rbacv1.RoleBinding
	)

	JustBeforeEach(func() {
		By("Creating test resources")

		// Create namespace with Athenz domain annotation
		namespace = corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "namespace-domain-test-",
				Annotations: map[string]string{
					"athenz.io/domain": "athenz.prod",
				},
			},
		}
		Expect(f.Client().Create(f.Context(), &namespace)).NotTo(HaveOccurred())

		// Create service account in the annotated namespace
		serviceAccount = corev1.ServiceAccount{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: namespace.Name,
				Name:      "api", // Simple service name without domain
			},
		}
		Expect(f.Client().Create(f.Context(), &serviceAccount)).NotTo(HaveOccurred())

		role = rbacv1.Role{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "namespace-domain-test-",
				Namespace:    namespace.Name,
			},
			Rules: []rbacv1.PolicyRule{{
				Verbs:     []string{"create"},
				APIGroups: []string{"cert-manager.io"},
				Resources: []string{"certificaterequests"},
			}},
		}
		Expect(f.Client().Create(f.Context(), &role)).NotTo(HaveOccurred())

		rolebinding = rbacv1.RoleBinding{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "namespace-domain-test-",
				Namespace:    namespace.Name,
			},
			RoleRef: rbacv1.RoleRef{
				APIGroup: "rbac.authorization.k8s.io",
				Kind:     "Role",
				Name:     role.Name,
			},
			Subjects: []rbacv1.Subject{{
				Kind:      "ServiceAccount",
				Name:      serviceAccount.Name,
				Namespace: namespace.Name,
			}},
		}
		Expect(f.Client().Create(f.Context(), &rolebinding)).NotTo(HaveOccurred())

		cl = f.Client()
	})

	JustAfterEach(func() {
		By("Cleaning up resources")
		Expect(f.Client().Delete(f.Context(), &rolebinding)).NotTo(HaveOccurred())
		Expect(f.Client().Delete(f.Context(), &role)).NotTo(HaveOccurred())
		Expect(f.Client().Delete(f.Context(), &serviceAccount)).NotTo(HaveOccurred())
	})

	It("should generate certificate with namespace-based domain when use-namespace-for-domain is true", func() {
		By("Creating a pod with namespace domain annotation")
		pod := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "namespace-domain-test-",
				Namespace:    namespace.Name,
			},
			Spec: corev1.PodSpec{
				ServiceAccountName: serviceAccount.Name,
				Containers: []corev1.Container{{
					Name:  "test",
					Image: "busybox",
					Command: []string{
						"sleep",
						"3600",
					},
					VolumeMounts: []corev1.VolumeMount{{
						Name:      "csi-driver-athenz",
						MountPath: "/certs",
					}},
				}},
				Volumes: []corev1.Volume{{
					Name: "csi-driver-athenz",
					VolumeSource: corev1.VolumeSource{
						CSI: &corev1.CSIVolumeSource{
							Driver:   "csi.cert-manager.athenz.io",
							ReadOnly: pointer.Bool(true),
							VolumeAttributes: map[string]string{
								"csi.cert-manager.athenz.io/use-namespace-for-domain": "true",
							},
						},
					},
				}},
			},
		}

		Expect(cl.Create(f.Context(), pod)).NotTo(HaveOccurred())

		By("Waiting for pod to be ready")
		Eventually(func() corev1.PodPhase {
			var currentPod corev1.Pod
			Expect(cl.Get(f.Context(), client.ObjectKey{Namespace: namespace.Name, Name: pod.Name}, &currentPod)).NotTo(HaveOccurred())
			return currentPod.Status.Phase
		}, time.Minute*2, time.Second*10).Should(Equal(corev1.PodRunning))

		By("Verifying certificate files are created")
		Eventually(func() error {
			var currentPod corev1.Pod
			Expect(cl.Get(f.Context(), client.ObjectKey{Namespace: namespace.Name, Name: pod.Name}, &currentPod)).NotTo(HaveOccurred())

			// Execute command to check if certificate files exist
			buf := new(bytes.Buffer)
			cmd := exec.Command(f.Config().KubectlBinPath, "exec", "-n"+namespace.Name, currentPod.Name, "-ctest", "--", "ls", "/certs")
			cmd.Stdout = buf
			cmd.Stderr = GinkgoWriter
			if err := cmd.Run(); err != nil {
				return err
			}

			// Check that tls.crt and tls.key exist
			if !contains(buf.String(), "tls.crt") || !contains(buf.String(), "tls.key") {
				return fmt.Errorf("certificate files not found: %s", buf.String())
			}

			return nil
		}, time.Minute*2, time.Second*10).Should(Succeed())

		By("Verifying certificate content has correct domain")
		Eventually(func() error {
			var currentPod corev1.Pod
			Expect(cl.Get(f.Context(), client.ObjectKey{Namespace: namespace.Name, Name: pod.Name}, &currentPod)).NotTo(HaveOccurred())

			// Read the certificate file
			buf := new(bytes.Buffer)
			cmd := exec.Command(f.Config().KubectlBinPath, "exec", "-n"+namespace.Name, currentPod.Name, "-ctest", "--", "cat", "/certs/tls.crt")
			cmd.Stdout = buf
			cmd.Stderr = GinkgoWriter
			if err := cmd.Run(); err != nil {
				return err
			}

			// Parse the certificate
			block, _ := pem.Decode([]byte(buf.String()))
			if block == nil {
				return fmt.Errorf("failed to decode PEM certificate")
			}

			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return fmt.Errorf("failed to parse certificate: %w", err)
			}

			// Verify the common name contains the namespace domain
			expectedCommonName := "athenz.prod.api"
			if cert.Subject.CommonName != expectedCommonName {
				return fmt.Errorf("expected common name %s, got %s", expectedCommonName, cert.Subject.CommonName)
			}

			// Verify DNS names contain the namespace domain
			expectedDNSName := "api.athenz-prod.svc.cluster.local"
			found := false
			for _, dnsName := range cert.DNSNames {
				if dnsName == expectedDNSName {
					found = true
					break
				}
			}
			if !found {
				return fmt.Errorf("expected DNS name %s not found in %v", expectedDNSName, cert.DNSNames)
			}

			return nil
		}, time.Minute*2, time.Second*10).Should(Succeed())

		Expect(f.Client().Delete(f.Context(), pod)).NotTo(HaveOccurred())
	})

	It("should use default domain extraction when use-namespace-for-domain is false", func() {

		serviceAccountWithDomain := corev1.ServiceAccount{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: namespace.Name,
				Name:      "athenz.api",
			},
		}
		Expect(f.Client().Create(f.Context(), &serviceAccountWithDomain)).NotTo(HaveOccurred())

		roleWithDomain := rbacv1.Role{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "default-domain-test-",
				Namespace:    namespace.Name,
			},
			Rules: []rbacv1.PolicyRule{{
				Verbs:     []string{"create"},
				APIGroups: []string{"cert-manager.io"},
				Resources: []string{"certificaterequests"},
			}},
		}
		Expect(f.Client().Create(f.Context(), &roleWithDomain)).NotTo(HaveOccurred())

		rolebindingWithDomain := rbacv1.RoleBinding{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "default-domain-test-",
				Namespace:    namespace.Name,
			},
			RoleRef: rbacv1.RoleRef{
				APIGroup: "rbac.authorization.k8s.io",
				Kind:     "Role",
				Name:     roleWithDomain.Name,
			},
			Subjects: []rbacv1.Subject{{
				Kind:      "ServiceAccount",
				Name:      serviceAccountWithDomain.Name,
				Namespace: namespace.Name,
			}},
		}
		Expect(f.Client().Create(f.Context(), &rolebindingWithDomain)).NotTo(HaveOccurred())

		By("Creating a pod without namespace domain annotation")
		pod := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "default-domain-test-",
				Namespace:    namespace.Name,
			},
			Spec: corev1.PodSpec{
				ServiceAccountName: serviceAccountWithDomain.Name,
				Containers: []corev1.Container{{
					Name:  "test",
					Image: "busybox",
					Command: []string{
						"sleep",
						"3600",
					},
					VolumeMounts: []corev1.VolumeMount{{
						Name:      "csi-driver-athenz",
						MountPath: "/certs",
					}},
				}},
				Volumes: []corev1.Volume{{
					Name: "csi-driver-athenz",
					VolumeSource: corev1.VolumeSource{
						CSI: &corev1.CSIVolumeSource{
							Driver:   "csi.cert-manager.athenz.io",
							ReadOnly: pointer.Bool(true),
							VolumeAttributes: map[string]string{
								"csi.cert-manager.athenz.io/use-namespace-for-domain": "false",
							},
						},
					},
				}},
			},
		}

		Expect(cl.Create(f.Context(), pod)).NotTo(HaveOccurred())

		By("Waiting for pod to be ready")
		Eventually(func() corev1.PodPhase {
			var currentPod corev1.Pod
			Expect(cl.Get(f.Context(), client.ObjectKey{Namespace: namespace.Name, Name: pod.Name}, &currentPod)).NotTo(HaveOccurred())
			return currentPod.Status.Phase
		}, time.Minute*2, time.Second*10).Should(Equal(corev1.PodRunning))

		By("Verifying certificate content uses default domain extraction")
		Eventually(func() error {
			var currentPod corev1.Pod
			Expect(cl.Get(f.Context(), client.ObjectKey{Namespace: namespace.Name, Name: pod.Name}, &currentPod)).NotTo(HaveOccurred())

			// Read the certificate file
			buf := new(bytes.Buffer)
			cmd := exec.Command(f.Config().KubectlBinPath, "exec", "-n"+namespace.Name, currentPod.Name, "-ctest", "--", "cat", "/certs/tls.crt")
			cmd.Stdout = buf
			cmd.Stderr = GinkgoWriter
			if err := cmd.Run(); err != nil {
				return err
			}

			// Parse the certificate
			block, _ := pem.Decode([]byte(buf.String()))
			if block == nil {
				return fmt.Errorf("failed to decode PEM certificate")
			}

			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return fmt.Errorf("failed to parse certificate: %w", err)
			}

			expectedCommonName := "athenz.api"
			if cert.Subject.CommonName != expectedCommonName {
				return fmt.Errorf("expected common name %s, got %s", expectedCommonName, cert.Subject.CommonName)
			}

			return nil
		}, time.Minute*2, time.Second*10).Should(Succeed())
	})

	It("should use default domain extraction when use-namespace-for-domain is not set", func() {

		By("Creating resources in the test namespace")
		serviceAccountWithDomain := corev1.ServiceAccount{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: namespace.Name,
				Name:      "athenz.api",
			},
		}
		Expect(f.Client().Create(f.Context(), &serviceAccountWithDomain)).NotTo(HaveOccurred())

		roleWithDomain := rbacv1.Role{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "no-domain-test-",
				Namespace:    namespace.Name,
			},
			Rules: []rbacv1.PolicyRule{{
				Verbs:     []string{"create"},
				APIGroups: []string{"cert-manager.io"},
				Resources: []string{"certificaterequests"},
			}},
		}
		Expect(f.Client().Create(f.Context(), &roleWithDomain)).NotTo(HaveOccurred())

		rolebindingWithDomain := rbacv1.RoleBinding{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "no-domain-test-",
				Namespace:    namespace.Name,
			},
			RoleRef: rbacv1.RoleRef{
				APIGroup: "rbac.authorization.k8s.io",
				Kind:     "Role",
				Name:     roleWithDomain.Name,
			},
			Subjects: []rbacv1.Subject{{
				Kind:      "ServiceAccount",
				Name:      serviceAccountWithDomain.Name,
				Namespace: namespace.Name,
			}},
		}
		Expect(f.Client().Create(f.Context(), &rolebindingWithDomain)).NotTo(HaveOccurred())

		By("Creating a pod without namespace domain attribute")
		pod := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "no-attribute-test-",
				Namespace:    namespace.Name,
			},
			Spec: corev1.PodSpec{
				ServiceAccountName: serviceAccountWithDomain.Name,
				Containers: []corev1.Container{{
					Name:  "test",
					Image: "busybox",
					Command: []string{
						"sleep",
						"3600",
					},
					VolumeMounts: []corev1.VolumeMount{{
						Name:      "csi-driver-athenz",
						MountPath: "/certs",
					}},
				}},
				Volumes: []corev1.Volume{{
					Name: "csi-driver-athenz",
					VolumeSource: corev1.VolumeSource{
						CSI: &corev1.CSIVolumeSource{
							Driver:   "csi.cert-manager.athenz.io",
							ReadOnly: pointer.Bool(true),
							// No use-namespace-for-domain attribute
						},
					},
				}},
			},
		}

		Expect(cl.Create(f.Context(), pod)).NotTo(HaveOccurred())

		By("Waiting for pod to be ready")
		Eventually(func() corev1.PodPhase {
			var currentPod corev1.Pod
			Expect(cl.Get(f.Context(), client.ObjectKey{Namespace: namespace.Name, Name: pod.Name}, &currentPod)).NotTo(HaveOccurred())
			return currentPod.Status.Phase
		}, time.Minute*2, time.Second*10).Should(Equal(corev1.PodRunning))

		By("Verifying certificate content uses default domain extraction")
		Eventually(func() error {
			var currentPod corev1.Pod
			Expect(cl.Get(f.Context(), client.ObjectKey{Namespace: namespace.Name, Name: pod.Name}, &currentPod)).NotTo(HaveOccurred())

			// Read the certificate file
			buf := new(bytes.Buffer)
			cmd := exec.Command(f.Config().KubectlBinPath, "exec", "-n"+namespace.Name, currentPod.Name, "-ctest", "--", "cat", "/certs/tls.crt")
			cmd.Stdout = buf
			cmd.Stderr = GinkgoWriter
			if err := cmd.Run(); err != nil {
				return err
			}

			// Parse the certificate
			block, _ := pem.Decode([]byte(buf.String()))
			if block == nil {
				return fmt.Errorf("failed to decode PEM certificate")
			}

			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return fmt.Errorf("failed to parse certificate: %w", err)
			}

			expectedCommonName := "athenz.api"
			if cert.Subject.CommonName != expectedCommonName {
				return fmt.Errorf("expected common name %s, got %s", expectedCommonName, cert.Subject.CommonName)
			}

			return nil
		}, time.Minute*2, time.Second*10).Should(Succeed())
	})

	It("should fail when namespace has no domain annotation but use-namespace-for-domain is true", func() {
		By("Creating resources within namespace without domain annotation")
		namespaceNoDomain := corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "no-domain-test-",
				// No athenz.io/domain annotation
			},
		}
		Expect(cl.Create(f.Context(), &namespaceNoDomain)).NotTo(HaveOccurred())

		serviceAccountNoDomain := corev1.ServiceAccount{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: namespaceNoDomain.Name,
				Name:      "api",
			},
		}
		Expect(cl.Create(f.Context(), &serviceAccountNoDomain)).NotTo(HaveOccurred())

		roleNoDomain := rbacv1.Role{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "no-domain-test-",
				Namespace:    namespaceNoDomain.Name,
			},
			Rules: []rbacv1.PolicyRule{{
				Verbs:     []string{"create"},
				APIGroups: []string{"cert-manager.io"},
				Resources: []string{"certificaterequests"},
			}},
		}
		Expect(f.Client().Create(f.Context(), &roleNoDomain)).NotTo(HaveOccurred())

		rolebindingNoDomain := rbacv1.RoleBinding{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "no-domain-test-",
				Namespace:    namespaceNoDomain.Name,
			},
			RoleRef: rbacv1.RoleRef{
				APIGroup: "rbac.authorization.k8s.io",
				Kind:     "Role",
				Name:     roleNoDomain.Name,
			},
			Subjects: []rbacv1.Subject{{
				Kind:      "ServiceAccount",
				Name:      serviceAccountNoDomain.Name,
				Namespace: namespaceNoDomain.Name,
			}},
		}
		Expect(f.Client().Create(f.Context(), &rolebindingNoDomain)).NotTo(HaveOccurred())

		By("Creating a pod with namespace domain annotation but no domain in namespace")
		pod := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "no-domain-test-",
				Namespace:    namespaceNoDomain.Name,
			},
			Spec: corev1.PodSpec{
				ServiceAccountName: serviceAccountNoDomain.Name,
				Containers: []corev1.Container{{
					Name:  "test",
					Image: "busybox",
					Command: []string{
						"sleep",
						"3600",
					},
					VolumeMounts: []corev1.VolumeMount{{
						Name:      "csi-driver-athenz",
						MountPath: "/certs",
					}},
				}},
				Volumes: []corev1.Volume{{
					Name: "csi-driver-athenz",
					VolumeSource: corev1.VolumeSource{
						CSI: &corev1.CSIVolumeSource{
							Driver:   "csi.cert-manager.athenz.io",
							ReadOnly: pointer.Bool(true),
							VolumeAttributes: map[string]string{
								"csi.cert-manager.athenz.io/use-namespace-for-domain": "true",
							},
						},
					},
				}},
			},
		}

		Expect(cl.Create(f.Context(), pod)).NotTo(HaveOccurred())

		By("Verifying pod fails to start due to missing domain annotation")
		Eventually(func() bool {
			var currentPod corev1.Pod
			Expect(cl.Get(f.Context(), client.ObjectKey{Namespace: namespaceNoDomain.Name, Name: pod.Name}, &currentPod)).NotTo(HaveOccurred())

			// Check if pod has failed events
			events := &corev1.EventList{}
			Expect(cl.List(f.Context(), events, client.InNamespace(namespaceNoDomain.Name))).NotTo(HaveOccurred())

			for _, event := range events.Items {
				if event.InvolvedObject.Name == pod.Name && event.Type == "Warning" {
					return true
				}
			}
			return false
		}, time.Minute*2, time.Second*10).Should(BeTrue())
	})
})

// Helper function to check if a string contains a substring
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		(len(s) > len(substr) && (s[:len(substr)] == substr || s[len(s)-len(substr):] == substr ||
			func() bool {
				for i := 1; i <= len(s)-len(substr); i++ {
					if s[i:i+len(substr)] == substr {
						return true
					}
				}
				return false
			}())))
}

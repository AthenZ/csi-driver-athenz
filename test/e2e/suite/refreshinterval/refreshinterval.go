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

package refreshinterval

import (
	"bytes"
	"os/exec"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/pointer"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/AthenZ/csi-driver-athenz/test/e2e/framework"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = framework.CasesDescribe("RefreshInterval", func() {
	f := framework.NewDefaultFramework("RefreshInterval")

	It("should issue certificate with custom refresh interval", func() {
		By("Creating service account, role, and rolebinding")

		serviceAccount := corev1.ServiceAccount{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "athenz.refresh-test",
				Namespace: f.Namespace.Name,
			},
		}
		Expect(f.Client().Create(f.Context(), &serviceAccount)).NotTo(HaveOccurred())

		role := rbacv1.Role{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "refresh-test",
				Namespace: f.Namespace.Name,
			},
			Rules: []rbacv1.PolicyRule{{
				Verbs:     []string{"create"},
				APIGroups: []string{"cert-manager.io"},
				Resources: []string{"certificaterequests"},
			}},
		}
		Expect(f.Client().Create(f.Context(), &role)).NotTo(HaveOccurred())

		rolebinding := rbacv1.RoleBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "refresh-test",
				Namespace: f.Namespace.Name,
			},
			RoleRef: rbacv1.RoleRef{
				APIGroup: "rbac.authorization.k8s.io",
				Kind:     "Role",
				Name:     role.Name,
			},
			Subjects: []rbacv1.Subject{{
				Kind:      "ServiceAccount",
				Name:      serviceAccount.Name,
				Namespace: f.Namespace.Name,
			}},
		}
		Expect(f.Client().Create(f.Context(), &rolebinding)).NotTo(HaveOccurred())

		By("Creating pod with custom refresh-interval of 1h")
		pod := corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "refresh-interval-test",
				Namespace: f.Namespace.Name,
			},
			Spec: corev1.PodSpec{
				Volumes: []corev1.Volume{{
					Name: "csi-driver-athenz",
					VolumeSource: corev1.VolumeSource{
						CSI: &corev1.CSIVolumeSource{
							Driver:   "csi.cert-manager.athenz.io",
							ReadOnly: pointer.Bool(true),
							VolumeAttributes: map[string]string{
								"csi.cert-manager.athenz.io/refresh-interval": "1h",
							},
						},
					},
				}},
				ServiceAccountName: "athenz.refresh-test",
				Containers: []corev1.Container{
					{
						Name:    "my-container",
						Image:   "busybox",
						Command: []string{"sleep", "10000"},
						VolumeMounts: []corev1.VolumeMount{
							{
								Name:      "csi-driver-athenz",
								MountPath: "/var/run/secrets/athenz.io",
							},
						},
					},
				},
			},
		}
		Expect(f.Client().Create(f.Context(), &pod)).NotTo(HaveOccurred())

		By("Waiting for pod to become ready")
		Eventually(func() bool {
			var p corev1.Pod
			Expect(f.Client().Get(f.Context(), client.ObjectKey{Namespace: f.Namespace.Name, Name: pod.Name}, &p)).NotTo(HaveOccurred())

			for _, c := range p.Status.Conditions {
				if c.Type == corev1.PodReady {
					return c.Status == corev1.ConditionTrue
				}
			}

			return false
		}, "60s", "1s").Should(BeTrue(), "expected pod to become ready in time")

		By("Verifying certificate was issued")
		buf := new(bytes.Buffer)
		cmd := exec.Command(f.Config().KubectlBinPath, "exec", "-n"+f.Namespace.Name, pod.Name, "-cmy-container", "--", "cat", "/var/run/secrets/athenz.io/tls.crt")
		cmd.Stdout = buf
		cmd.Stderr = GinkgoWriter
		Expect(cmd.Run()).To(Succeed())
		Expect(buf.Len()).To(BeNumerically(">", 0), "expected certificate file to not be empty")

		By("Cleaning up resources")
		Expect(f.Client().Delete(f.Context(), &pod)).NotTo(HaveOccurred())
		Expect(f.Client().Delete(f.Context(), &rolebinding)).NotTo(HaveOccurred())
		Expect(f.Client().Delete(f.Context(), &role)).NotTo(HaveOccurred())
		Expect(f.Client().Delete(f.Context(), &serviceAccount)).NotTo(HaveOccurred())
	})

	It("should fail to mount volume with invalid refresh interval", func() {
		By("Creating service account, role, and rolebinding")

		serviceAccount := corev1.ServiceAccount{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "athenz.invalid-refresh-test",
				Namespace: f.Namespace.Name,
			},
		}
		Expect(f.Client().Create(f.Context(), &serviceAccount)).NotTo(HaveOccurred())

		role := rbacv1.Role{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "invalid-refresh-test",
				Namespace: f.Namespace.Name,
			},
			Rules: []rbacv1.PolicyRule{{
				Verbs:     []string{"create"},
				APIGroups: []string{"cert-manager.io"},
				Resources: []string{"certificaterequests"},
			}},
		}
		Expect(f.Client().Create(f.Context(), &role)).NotTo(HaveOccurred())

		rolebinding := rbacv1.RoleBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "invalid-refresh-test",
				Namespace: f.Namespace.Name,
			},
			RoleRef: rbacv1.RoleRef{
				APIGroup: "rbac.authorization.k8s.io",
				Kind:     "Role",
				Name:     role.Name,
			},
			Subjects: []rbacv1.Subject{{
				Kind:      "ServiceAccount",
				Name:      serviceAccount.Name,
				Namespace: f.Namespace.Name,
			}},
		}
		Expect(f.Client().Create(f.Context(), &rolebinding)).NotTo(HaveOccurred())

		By("Creating pod with invalid refresh-interval")
		pod := corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "invalid-refresh-interval-test",
				Namespace: f.Namespace.Name,
			},
			Spec: corev1.PodSpec{
				Volumes: []corev1.Volume{{
					Name: "csi-driver-athenz",
					VolumeSource: corev1.VolumeSource{
						CSI: &corev1.CSIVolumeSource{
							Driver:   "csi.cert-manager.athenz.io",
							ReadOnly: pointer.Bool(true),
							VolumeAttributes: map[string]string{
								"csi.cert-manager.athenz.io/refresh-interval": "invalid",
							},
						},
					},
				}},
				ServiceAccountName: "athenz.invalid-refresh-test",
				Containers: []corev1.Container{
					{
						Name:    "my-container",
						Image:   "busybox",
						Command: []string{"sleep", "10000"},
						VolumeMounts: []corev1.VolumeMount{
							{
								Name:      "csi-driver-athenz",
								MountPath: "/var/run/secrets/athenz.io",
							},
						},
					},
				},
			},
		}
		Expect(f.Client().Create(f.Context(), &pod)).NotTo(HaveOccurred())

		By("Verifying pod fails to become ready due to invalid refresh interval")
		Consistently(func() bool {
			var p corev1.Pod
			Expect(f.Client().Get(f.Context(), client.ObjectKey{Namespace: f.Namespace.Name, Name: pod.Name}, &p)).NotTo(HaveOccurred())

			for _, c := range p.Status.Conditions {
				if c.Type == corev1.PodReady {
					return c.Status == corev1.ConditionTrue
				}
			}

			return false
		}, "30s", "1s").Should(BeFalse(), "expected pod to NOT become ready due to invalid refresh interval")

		By("Cleaning up resources")
		Expect(f.Client().Delete(f.Context(), &pod)).NotTo(HaveOccurred())
		Expect(f.Client().Delete(f.Context(), &rolebinding)).NotTo(HaveOccurred())
		Expect(f.Client().Delete(f.Context(), &role)).NotTo(HaveOccurred())
		Expect(f.Client().Delete(f.Context(), &serviceAccount)).NotTo(HaveOccurred())
	})
})

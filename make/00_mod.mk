# Copyright The Athenz Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

repo_name := github.com/AthenZ/csi-driver-athenz

kind_cluster_name := csi-driver-athenz
kind_cluster_config := $(bin_dir)/scratch/kind_cluster.yaml

oci_platforms := linux/amd64,linux/arm64

build_names := manager approver

go_manager_main_dir := ./cmd/csi
go_manager_mod_dir := .
go_manager_ldflags := -X $(repo_name)/internal/version.AppVersion=$(VERSION) -X $(repo_name)/internal/version.GitCommit=$(GITCOMMIT)
oci_manager_base_image_flavor := csi-static
oci_manager_image_name := docker.io/athenz/csi-driver-athenz
oci_manager_image_tag := $(VERSION)
oci_manager_image_name_development := athenz.local/csi-driver-athenz

go_approver_main_dir := ./cmd/approver
go_approver_mod_dir := .
go_approver_ldflags := -X $(repo_name)/internal/version.AppVersion=$(VERSION) -X $(repo_name)/internal/version.GitCommit=$(GITCOMMIT)
oci_approver_base_image_flavor := static
oci_approver_image_name := docker.io/athenz/csi-driver-athenz-approver
oci_approver_image_tag := $(VERSION)
oci_approver_image_name_development := athenz.local/csi-driver-athenz-approver

deploy_name := csi-driver-athenz
deploy_namespace := cert-manager

api_docs_outfile := docs/api/api.md
api_docs_package := $(repo_name)/pkg/apis/trust/v1alpha1
api_docs_branch := main

helm_chart_source_dir := deploy/charts/csi-driver-athenz
helm_chart_name := csi-driver-athenz
helm_chart_version := $(VERSION)
helm_labels_template_name := csi-driver-athenz.labels
helm_docs_use_helm_tool := 1
helm_generate_schema := 1 
helm_verify_values := 1 

define helm_values_mutation_function
$(YQ) \
	'( .image.repository.driver = "$(oci_manager_image_name)" ) | \
	( .image.repository.approver = "$(oci_approver_image_name)" ) | \
	( .image.tag = "$(oci_manager_image_tag)" )' \
	$1 --inplace
endef

images_amd64 ?=
images_arm64 ?=

images_amd64 += docker.io/library/busybox:1.36.1-musl@sha256:b9d056b83bb6446fee29e89a7fcf10203c562c1f59586a6e2f39c903597bda34
images_arm64 += docker.io/library/busybox:1.36.1-musl@sha256:648143a312f16e5b5a6f64dfa4024a281fb4a30467500ca8b0091a9984f1c751
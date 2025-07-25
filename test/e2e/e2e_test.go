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

package e2e

import (
	"flag"
	"testing"
	"time"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
	"k8s.io/apimachinery/pkg/util/wait"

	"github.com/AthenZ/csi-driver-athenz/test/e2e/framework/config"

	_ "github.com/AthenZ/csi-driver-athenz/test/e2e/suite"
)

func init() {
	config.GetConfig().AddFlags(flag.CommandLine)

	wait.ForeverTestTimeout = time.Second * 60
}

// Test_e2e runs the full suite of smoke tests against csi-driver-athenz
func Test_e2e(t *testing.T) {
	flag.Parse()
	if err := config.GetConfig().Complete(); err != nil {
		t.Fatal(err)
	}

	gomega.RegisterFailHandler(ginkgo.Fail)

	suiteConfig, reporterConfig := ginkgo.GinkgoConfiguration()

	// Turn on verbose by default to get spec names
	reporterConfig.Verbose = true
	// Turn on EmitSpecProgress to get spec progress (especially on interrupt)
	suiteConfig.EmitSpecProgress = true
	// Randomize specs as well as suites
	suiteConfig.RandomizeAllSpecs = true

	ginkgo.RunSpecs(t, "csi-driver-athenz e2e suite", suiteConfig, reporterConfig)
}

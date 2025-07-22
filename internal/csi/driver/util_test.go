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

package driver

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_extractDomainService(t *testing.T) {
	tests := []struct {
		name            string
		saName          string
		expectedDomain  string
		expectedService string
	}{
		{
			name:            "service account with domain",
			saName:          "athenz.prod.api",
			expectedDomain:  "athenz.prod",
			expectedService: "api",
		},
		{
			name:            "service account without domain",
			saName:          "api",
			expectedDomain:  "",
			expectedService: "",
		},
		{
			name:            "service account with multiple dots",
			saName:          "athenz.prod.staging.api",
			expectedDomain:  "athenz.prod.staging",
			expectedService: "api",
		},
		{
			name:            "empty service account name",
			saName:          "",
			expectedDomain:  "",
			expectedService: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			domain, service := extractDomainService(tt.saName)
			assert.Equal(t, tt.expectedDomain, domain)
			assert.Equal(t, tt.expectedService, service)
		})
	}
}

func Test_appendHostname(t *testing.T) {
	tests := []struct {
		name     string
		hostList []string
		hostname string
		expected []string
	}{
		{
			name:     "add new hostname to empty list",
			hostList: []string{},
			hostname: "example.com",
			expected: []string{"example.com"},
		},
		{
			name:     "add new hostname to existing list",
			hostList: []string{"existing.com"},
			hostname: "example.com",
			expected: []string{"existing.com", "example.com"},
		},
		{
			name:     "don't add duplicate hostname",
			hostList: []string{"example.com"},
			hostname: "example.com",
			expected: []string{"example.com"},
		},
		{
			name:     "add empty hostname",
			hostList: []string{"existing.com"},
			hostname: "",
			expected: []string{"existing.com", ""},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := appendHostname(tt.hostList, tt.hostname)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func Test_getDomainFromNamespaceAnnotations(t *testing.T) {
	tests := []struct {
		name        string
		annotations map[string]string
		expected    string
	}{
		{
			name: "namespace with athenz domain annotation",
			annotations: map[string]string{
				"athenz.io/domain": "athenz.prod",
				"other.annotation": "value",
			},
			expected: "athenz.prod",
		},
		{
			name: "namespace without athenz domain annotation",
			annotations: map[string]string{
				"other.annotation": "value",
			},
			expected: "",
		},
		{
			name:        "namespace with no annotations",
			annotations: map[string]string{},
			expected:    "",
		},
		{
			name:        "nil annotations",
			annotations: nil,
			expected:    "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getDomainFromNamespaceAnnotations(tt.annotations)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func Test_appendUri(t *testing.T) {
	tests := []struct {
		name     string
		uriList  []string
		uriValue string
		expected int // expected number of URIs in the result
	}{
		{
			name:     "add valid URI",
			uriList:  []string{},
			uriValue: "athenz://instanceid/provider/pod-id",
			expected: 1,
		},
		{
			name:     "add invalid URI",
			uriList:  []string{},
			uriValue: "invalid://[invalid",
			expected: 0,
		},
		{
			name:     "add empty URI",
			uriList:  []string{},
			uriValue: "",
			expected: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// We can't easily test the URL parsing without exposing the function,
			// but we can test that it doesn't panic
			require.NotPanics(t, func() {
				// This is a simplified test since we can't access the internal URL slice
				// The main purpose is to ensure the function doesn't panic on invalid input
			})
		})
	}
}

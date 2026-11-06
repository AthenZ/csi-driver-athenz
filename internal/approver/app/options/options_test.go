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

package options

import (
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"
)

func Test_MaxConcurrentReconciles(t *testing.T) {
	parse := func(t *testing.T, args ...string) *Options {
		t.Helper()
		o := New()
		cmd := &cobra.Command{}
		o.Prepare(cmd)
		require.NoError(t, cmd.ParseFlags(args))
		return o
	}

	t.Run("default-is-one", func(t *testing.T) {
		o := parse(t)
		require.Equal(t, 1, o.Controller.MaxConcurrentReconciles)
		require.NoError(t, o.validate())
	})

	t.Run("flag-sets-value", func(t *testing.T) {
		o := parse(t, "--max-concurrent-reconciles=8")
		require.Equal(t, 8, o.Controller.MaxConcurrentReconciles)
		require.NoError(t, o.validate())
	})

	for _, v := range []string{"0", "-1"} {
		t.Run("rejects-"+v, func(t *testing.T) {
			o := parse(t, "--max-concurrent-reconciles="+v)
			require.ErrorContains(t, o.validate(), "--max-concurrent-reconciles")
		})
	}
}

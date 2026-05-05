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

//go:build linux

package driver

import (
	"errors"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	mount "k8s.io/mount-utils"
)

const (
	testInmemfsPath = "/data/inmemfs"
	testTargetPath  = "/var/lib/kubelet/pods/abc/volumes/csi/mount"
	inmemfsDev      = uint64(100) // current driver's tmpfs device
	staleDev        = uint64(200) // old driver's device
	anotherStaleDev = uint64(300) // second stale layer device
)

// fakeMounter implements mount.Interface for testing.
// Only IsMountPoint and Unmount are invoked by staleMountFixingMounter.
type fakeMounter struct {
	isMountPointFn func(string) (bool, error)
	// unmountResults are returned in order on successive Unmount calls.
	// Once exhausted, Unmount returns nil.
	unmountResults []error
	unmountIdx     int
	unmountCalls   int
}

func (f *fakeMounter) IsMountPoint(file string) (bool, error) { return f.isMountPointFn(file) }
func (f *fakeMounter) Unmount(_ string) error {
	f.unmountCalls++
	if f.unmountIdx < len(f.unmountResults) {
		err := f.unmountResults[f.unmountIdx]
		f.unmountIdx++
		return err
	}
	return nil
}
func (f *fakeMounter) Mount(_, _, _ string, _ []string) error                                    { return nil }
func (f *fakeMounter) MountSensitive(_, _, _ string, _, _ []string) error                        { return nil }
func (f *fakeMounter) MountSensitiveWithoutSystemd(_, _, _ string, _, _ []string) error          { return nil }
func (f *fakeMounter) MountSensitiveWithoutSystemdWithMountFlags(_, _, _ string, _, _, _ []string) error {
	return nil
}
func (f *fakeMounter) List() ([]mount.MountPoint, error)         { return nil, nil }
func (f *fakeMounter) IsLikelyNotMountPoint(_ string) (bool, error) { return false, nil }
func (f *fakeMounter) CanSafelySkipMountPointCheck() bool        { return false }
func (f *fakeMounter) GetMountRefs(_ string) ([]string, error)   { return nil, nil }

// statCall is a single canned result for a stat call.
type statCall struct {
	dev uint64
	err error
}

// makeStatFn returns a stat function that plays back canned results per path in
// order. Calling a path more times than configured returns an error so tests
// surface unexpected extra calls.
func makeStatFn(perPath map[string][]statCall) func(string, *syscall.Stat_t) error {
	idx := map[string]int{}
	return func(path string, s *syscall.Stat_t) error {
		calls, ok := perPath[path]
		if !ok {
			return errors.New("unexpected stat path: " + path)
		}
		i := idx[path]
		if i >= len(calls) {
			return errors.New("stat called more times than expected for: " + path)
		}
		idx[path]++
		if calls[i].err != nil {
			return calls[i].err
		}
		s.Dev = calls[i].dev
		return nil
	}
}

func newTestMounter(base *fakeMounter, statFn func(string, *syscall.Stat_t) error) *staleMountFixingMounter {
	return &staleMountFixingMounter{
		Interface:   base,
		inmemfsPath: testInmemfsPath,
		stat:        statFn,
	}
}

// --- IsMountPoint tests ---

func TestStaleMountFixingMounter_IsMountPoint(t *testing.T) {
	errStat := errors.New("stat error")
	errMount := errors.New("mount error")

	tests := []struct {
		name           string
		baseMnt        bool
		baseErr        error
		statCalls      map[string][]statCall
		wantMnt        bool
		wantErr        bool
	}{
		{
			name:    "not a mount point — base returns false",
			baseMnt: false,
			wantMnt: false,
		},
		{
			name:    "base IsMountPoint returns error",
			baseMnt: false,
			baseErr: errMount,
			wantMnt: false,
			wantErr: true,
		},
		{
			name:    "stat(inmemfsPath) fails — assume valid to avoid disruption",
			baseMnt: true,
			statCalls: map[string][]statCall{
				testInmemfsPath: {{err: errStat}},
			},
			wantMnt: true,
		},
		{
			name:    "stat(file) fails — assume valid",
			baseMnt: true,
			statCalls: map[string][]statCall{
				testInmemfsPath: {{dev: inmemfsDev}},
				testTargetPath:  {{err: errStat}},
			},
			wantMnt: true,
		},
		{
			name:    "devices match — valid mount on current tmpfs",
			baseMnt: true,
			statCalls: map[string][]statCall{
				testInmemfsPath: {{dev: inmemfsDev}},
				testTargetPath:  {{dev: inmemfsDev}},
			},
			wantMnt: true,
		},
		{
			name:    "devices differ — stale bind mount from previous driver",
			baseMnt: true,
			statCalls: map[string][]statCall{
				testInmemfsPath: {{dev: inmemfsDev}},
				testTargetPath:  {{dev: staleDev}},
			},
			wantMnt: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			base := &fakeMounter{
				isMountPointFn: func(_ string) (bool, error) { return tt.baseMnt, tt.baseErr },
			}
			m := newTestMounter(base, makeStatFn(tt.statCalls))

			got, err := m.IsMountPoint(testTargetPath)

			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			assert.Equal(t, tt.wantMnt, got)
		})
	}
}

// --- Unmount tests ---

func TestStaleMountFixingMounter_Unmount(t *testing.T) {
	errUnmount := errors.New("unmount error")
	errStat := errors.New("stat error")

	tests := []struct {
		name              string
		unmountResults    []error
		statCalls         map[string][]statCall
		wantErr           bool
		wantUnmountCalls  int
	}{
		{
			name:             "base Unmount fails — error returned immediately",
			unmountResults:   []error{errUnmount},
			wantErr:          true,
			wantUnmountCalls: 1,
		},
		{
			name:           "stat(inmemfsPath) fails after unmount — return nil",
			unmountResults: []error{nil},
			statCalls: map[string][]statCall{
				testInmemfsPath: {{err: errStat}},
			},
			wantUnmountCalls: 1,
		},
		{
			name:           "stat(target) fails immediately — nothing left mounted",
			unmountResults: []error{nil},
			statCalls: map[string][]statCall{
				testInmemfsPath: {{dev: inmemfsDev}},
				testTargetPath:  {{err: errStat}},
			},
			wantUnmountCalls: 1,
		},
		{
			name:           "target device matches current tmpfs — no stale layer",
			unmountResults: []error{nil},
			statCalls: map[string][]statCall{
				testInmemfsPath: {{dev: inmemfsDev}},
				testTargetPath:  {{dev: inmemfsDev}},
			},
			wantUnmountCalls: 1,
		},
		{
			name:           "one stale layer — cleaned up by loop",
			unmountResults: []error{nil, nil},
			statCalls: map[string][]statCall{
				testInmemfsPath: {{dev: inmemfsDev}},
				// first loop iteration: stale device → triggers second Unmount
				// second loop iteration: stat fails → loop exits
				testTargetPath: {{dev: staleDev}, {err: errStat}},
			},
			wantUnmountCalls: 2,
		},
		{
			name:           "two stale layers — both cleaned up by loop",
			unmountResults: []error{nil, nil, nil},
			statCalls: map[string][]statCall{
				testInmemfsPath: {{dev: inmemfsDev}},
				testTargetPath: {
					{dev: staleDev},        // iteration 1: stale → unmount
					{dev: anotherStaleDev}, // iteration 2: still stale → unmount
					{err: errStat},         // iteration 3: nothing left → exit
				},
			},
			wantUnmountCalls: 3,
		},
		{
			name:           "loop Unmount fails — exits cleanly without error",
			unmountResults: []error{nil, errUnmount},
			statCalls: map[string][]statCall{
				testInmemfsPath: {{dev: inmemfsDev}},
				testTargetPath:  {{dev: staleDev}},
			},
			wantUnmountCalls: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			base := &fakeMounter{
				isMountPointFn: func(_ string) (bool, error) { return false, nil },
				unmountResults: tt.unmountResults,
			}
			m := newTestMounter(base, makeStatFn(tt.statCalls))

			err := m.Unmount(testTargetPath)

			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			assert.Equal(t, tt.wantUnmountCalls, base.unmountCalls)
		})
	}
}

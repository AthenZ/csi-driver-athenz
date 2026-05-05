//go:build linux

package driver

import (
	"syscall"

	"k8s.io/mount-utils"
)

// staleMountFixingMounter wraps mount.Interface to detect and recover from stale
// bind mounts left behind when the CSI driver restarts.
//
// Root cause: csi-lib mounts a private tmpfs at <data-root>/inmemfs on startup.
// When the driver pod is replaced (new deployment), the new container gets a fresh
// tmpfs with a new device number. The old bind mounts in the pod's mount namespace
// still reference directory inodes on the old (now-gone) tmpfs. csi-lib's
// NodePublishVolume sees IsMountPoint(targetPath)==true and returns early without
// re-binding, so the pod keeps reading stale certificate data forever.
//
// Fix: compare the device number of the path resolved by stat(2) against the
// device number of the current driver's tmpfs. stat(2) resolves the topmost mount
// at the path and works regardless of mount-namespace visibility (e.g. GKE's
// containerized mounter). A mismatch means the bind mount is stale. IsMountPoint
// returns false WITHOUT unmounting, causing csi-lib to mount the fresh data dir on
// top. Linux stacks the new bind mount over the stale one atomically — readers see
// fresh certs with no ENOENT window. Workload pods must set
// mountPropagation: HostToContainer on the CSI volumeMount for the new host-level
// mount to propagate into running containers. The shadowed stale mount is cleaned
// up by Unmount when the volume is later unpublished.
type staleMountFixingMounter struct {
	mount.Interface
	// inmemfsPath is the path where csi-lib mounts its tmpfs, i.e.
	// filepath.Join(dataRoot, "inmemfs"). Used to obtain the current tmpfs device number.
	inmemfsPath string
	// stat is syscall.Stat; injectable for testing.
	stat func(string, *syscall.Stat_t) error
}

func newStaleMountFixingMounter(inmemfsPath string) mount.Interface {
	return &staleMountFixingMounter{
		Interface:   mount.New(""),
		inmemfsPath: inmemfsPath,
		stat:        syscall.Stat,
	}
}

// IsMountPoint returns false when the device at file differs from the current
// driver tmpfs device, indicating a stale bind mount from a previous driver
// instance. It does NOT unmount — see Unmount for cleanup.
func (m *staleMountFixingMounter) IsMountPoint(file string) (bool, error) {
	isMnt, err := m.Interface.IsMountPoint(file)
	if !isMnt || err != nil {
		return isMnt, err
	}

	var inmemfsStat syscall.Stat_t
	if err := m.stat(m.inmemfsPath, &inmemfsStat); err != nil {
		// tmpfs not yet accessible — assume mount is valid to avoid disruption
		return true, nil
	}

	var fileStat syscall.Stat_t
	if err := m.stat(file, &fileStat); err != nil {
		return true, nil
	}

	if fileStat.Dev == inmemfsStat.Dev {
		// Bind mount is on the current tmpfs — valid
		return true, nil
	}

	// Different device: bind is from a previous driver instance. Return false
	// WITHOUT unmounting so csi-lib mounts the fresh data dir on top, atomically
	// shadowing the stale one with no ENOENT window for readers.
	return false, nil
}

// Unmount removes the top bind mount at target. If shadowed stale mounts are
// then exposed underneath (left by the mount-on-top stale fix across one or
// more driver restarts), they are removed too so the path is left clean for
// kubelet. syscall.Stat is used instead of IsMountPoint because the driver
// pod's /proc/self/mountinfo does not reflect bind mounts in GKE's
// containerized mounter environment.
func (m *staleMountFixingMounter) Unmount(target string) error {
	if err := m.Interface.Unmount(target); err != nil {
		return err
	}
	var inmemfsStat syscall.Stat_t
	if err := m.stat(m.inmemfsPath, &inmemfsStat); err != nil {
		return nil
	}
	for {
		var fileStat syscall.Stat_t
		if err := m.stat(target, &fileStat); err != nil {
			return nil
		}
		if fileStat.Dev == inmemfsStat.Dev {
			return nil
		}
		// Stale mount from a previous driver instance is exposed. Remove it.
		// Loop continues until no stale layers remain or Unmount fails (EINVAL
		// when nothing is mounted at target).
		if err := m.Interface.Unmount(target); err != nil {
			return nil
		}
	}
}

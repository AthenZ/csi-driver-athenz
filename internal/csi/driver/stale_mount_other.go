//go:build !linux

package driver

import "k8s.io/mount-utils"

func newStaleMountFixingMounter(_ string) mount.Interface {
	return mount.New("")
}

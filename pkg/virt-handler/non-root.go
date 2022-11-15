//go:build linux && amd64

package virthandler

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"

	// #include <linux/sched.h>
	// #include <linux/sched/types.h>
	// typedef struct sched_param sched_param;
	"C"

	k8sv1 "k8s.io/api/core/v1"

	v1 "kubevirt.io/api/core/v1"

	"kubevirt.io/client-go/log"
	diskutils "kubevirt.io/kubevirt/pkg/ephemeral-disk-utils"
	hostdisk "kubevirt.io/kubevirt/pkg/host-disk"
	"kubevirt.io/kubevirt/pkg/safepath"
	"kubevirt.io/kubevirt/pkg/storage/types"
	"kubevirt.io/kubevirt/pkg/virt-handler/isolation"
)

type SchedParam C.sched_param
type Policy uint32
type maskType bool

const (
	SCHED_FIFO Policy   = C.SCHED_FIFO
	enabled    maskType = true
	disabled   maskType = false
)

var (
	// parse CPU Mask expressions
	cpuRangeRegex  = regexp.MustCompile(`^(\d+)-(\d+)$`)
	negateCPURegex = regexp.MustCompile(`^\^(\d+)$`)
	singleCPURegex = regexp.MustCompile(`^(\d+)$`)

	// parse thread comm value expression
	vcpuRegex = regexp.MustCompile(`^CPU (\d+)/KVM$`) // These threads follow this naming pattern as their command value (/proc/{pid}/task/{taskid}/comm)
// QEMU uses threads to represent VCPUs.

)

func changeOwnershipOfBlockDevices(vmi *v1.VirtualMachineInstance, res isolation.IsolationResult) error {
	volumeModes := map[string]*k8sv1.PersistentVolumeMode{}
	for _, volumeStatus := range vmi.Status.VolumeStatus {
		if volumeStatus.PersistentVolumeClaimInfo != nil {
			volumeModes[volumeStatus.Name] = volumeStatus.PersistentVolumeClaimInfo.VolumeMode
		}
	}

	for i := range vmi.Spec.Volumes {
		volume := vmi.Spec.Volumes[i]
		if volume.VolumeSource.PersistentVolumeClaim == nil {
			continue
		}

		volumeMode, exists := volumeModes[volume.Name]
		if !exists {
			return fmt.Errorf("missing volume status for volume %s", volume.Name)
		}

		if !types.IsPVCBlock(volumeMode) {
			continue
		}
		devPath, err := isolation.SafeJoin(res, string(filepath.Separator), "dev", vmi.Spec.Volumes[i].Name)
		if err != nil {
			return nil
		}
		if err := diskutils.DefaultOwnershipManager.SetFileOwnership(devPath); err != nil {
			return err
		}

	}
	return nil
}

func changeOwnership(path *safepath.Path) error {
	err := diskutils.DefaultOwnershipManager.SetFileOwnership(path)
	if err != nil {
		return err
	}
	return nil
}

// changeOwnershipOfHostDisks needs unmodified vmi (not passed to ReplacePVCByHostDisk function)
func changeOwnershipOfHostDisks(vmiWithAllPVCs *v1.VirtualMachineInstance, res isolation.IsolationResult) error {
	for i := range vmiWithAllPVCs.Spec.Volumes {
		if volumeSource := &vmiWithAllPVCs.Spec.Volumes[i].VolumeSource; volumeSource.HostDisk != nil {
			volumeName := vmiWithAllPVCs.Spec.Volumes[i].Name
			diskPath := hostdisk.GetMountedHostDiskPath(volumeName, volumeSource.HostDisk.Path)

			_, err := os.Stat(diskPath)
			if err != nil {
				if errors.Is(err, os.ErrNotExist) {
					diskDir := hostdisk.GetMountedHostDiskDir(volumeName)
					path, err := isolation.SafeJoin(res, diskDir)
					if err != nil {
						return fmt.Errorf("Failed to change ownership of HostDisk dir %s, %s", volumeName, err)
					}
					if err := changeOwnership(path); err != nil {
						return fmt.Errorf("Failed to change ownership of HostDisk dir %s, %s", volumeName, err)
					}
					continue
				}
				return fmt.Errorf("Failed to recognize if hostdisk contains image, %s", err)
			}

			path, err := isolation.SafeJoin(res, diskPath)
			if err != nil {
				return fmt.Errorf("Failed to change ownership of HostDisk image: %s", err)
			}
			err = changeOwnership(path)
			if err != nil {
				return fmt.Errorf("Failed to change ownership of HostDisk image: %s", err)
			}

		}
	}
	return nil
}

func (d *VirtualMachineController) prepareStorage(vmi *v1.VirtualMachineInstance, res isolation.IsolationResult) error {
	if err := changeOwnershipOfBlockDevices(vmi, res); err != nil {
		return err
	}
	return changeOwnershipOfHostDisks(vmi, res)
}

func getTapDevices(vmi *v1.VirtualMachineInstance) []string {
	macvtap := map[string]bool{}
	for _, inf := range vmi.Spec.Domain.Devices.Interfaces {
		if inf.Macvtap != nil {
			macvtap[inf.Name] = true
		}
	}

	tapDevices := []string{}
	for _, net := range vmi.Spec.Networks {
		_, ok := macvtap[net.Name]
		if ok {
			tapDevices = append(tapDevices, net.Multus.NetworkName)
		}
	}
	return tapDevices
}

func (d *VirtualMachineController) prepareTap(vmi *v1.VirtualMachineInstance, res isolation.IsolationResult) error {
	tapDevices := getTapDevices(vmi)
	for _, tap := range tapDevices {
		path, err := isolation.SafeJoin(res, "sys", "class", "net", tap, "ifindex")
		if err != nil {
			return err
		}
		index, err := func(path *safepath.Path) (int, error) {
			df, err := safepath.OpenAtNoFollow(path)
			if err != nil {
				return 0, err
			}
			defer df.Close()
			b, err := os.ReadFile(df.SafePath())
			if err != nil {
				return 0, fmt.Errorf("Failed to read if index, %v", err)
			}

			return strconv.Atoi(strings.TrimSpace(string(b)))
		}(path)
		if err != nil {
			return err
		}

		pathToTap, err := isolation.SafeJoin(res, "dev", fmt.Sprintf("tap%d", index))
		if err != nil {
			return err
		}

		if err := diskutils.DefaultOwnershipManager.SetFileOwnership(pathToTap); err != nil {
			return err
		}
	}
	return nil

}

func (*VirtualMachineController) prepareVFIO(vmi *v1.VirtualMachineInstance, res isolation.IsolationResult) error {
	vfioBasePath, err := isolation.SafeJoin(res, "dev", "vfio")
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
	}
	vfioPath, err := safepath.JoinNoFollow(vfioBasePath, "vfio")
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
	}
	err = safepath.ChmodAtNoFollow(vfioPath, 0666)
	if err != nil {
		return err
	}

	var files []os.DirEntry
	err = vfioBasePath.ExecuteNoFollow(func(safePath string) (err error) {
		files, err = os.ReadDir(safePath)
		return err
	})
	if err != nil {
		return err
	}

	for _, group := range files {
		if group.Name() == "vfio" {
			continue
		}
		groupPath, err := safepath.JoinNoFollow(vfioBasePath, group.Name())
		if err != nil {
			return err
		}
		if err := diskutils.DefaultOwnershipManager.SetFileOwnership(groupPath); err != nil {
			return err
		}
	}
	return nil
}

func (d *VirtualMachineController) prepareVCPUSchedulerAndPriority(vmi *v1.VirtualMachineInstance, res isolation.IsolationResult) error {
	log.Log.Object(vmi).Infof(">>>>>>>>>>>>>>Is is a realtime VM? %t", vmi.IsRealtimeEnabled())
	if vmi.IsRealtimeEnabled() {
		qemuProcess, err := isolation.GetQEMUProcess(res.PPid())
		if err != nil {
			return err
		}
		vcpus, err := getVCPUThreadIDs(qemuProcess.Pid())
		if err != nil {
			return err
		}
		mask, err := parseCPUMask(vmi.Spec.Domain.CPU.Realtime.Mask)
		if err != nil {
			return err
		}
		log.Log.Object(vmi).Infof(">>>>>>>>>>>>>>Mask is %+v", mask)
		for vcpuID, threadID := range vcpus {
			if isRealtimeVCPU(mask, vcpuID) {
				// param := SchedParam{sched_priority: -1}
				tid, err := strconv.Atoi(threadID)
				if err != nil {
					return err
				}
				log.Log.Object(vmi).Infof(">>>>>>>>>>>>>>Setting scheduler and priority to thread ID %d", tid)
				// schedSetScheduler(tid, SCHED_FIFO, param)
			}
		}
	}
	return nil
}

func isRealtimeVCPU(parsedMask map[string]maskType, vcpuID string) bool {
	if len(parsedMask) == 0 {
		return true
	}
	if t, ok := parsedMask[vcpuID]; ok {
		return t == enabled
	}
	return false
}

func isVCPU(comm []byte) (string, bool) {
	if !vcpuRegex.MatchString(string(comm)) {
		return "", false
	}
	v := vcpuRegex.FindSubmatch(comm)
	return string(v[1]), true
}

func getVCPUThreadIDs(pid int) (map[string]string, error) {

	p := filepath.Join(string(os.PathSeparator), "proc", strconv.Itoa(pid), "task")
	d, err := os.ReadDir(p)
	if err != nil {
		return nil, err
	}
	ret := map[string]string{}
	for _, f := range d {
		if f.IsDir() {
			c, err := os.ReadFile(filepath.Join(p, f.Name(), "comm"))
			if err != nil {
				return nil, err
			}
			if v, ok := isVCPU(c); ok {
				ret[v] = f.Name()
			}
		}
	}
	return ret, nil
}

// parseCPUMask parses the mask and maps the results into a structure that contains which
// CPUs are enabled or disabled for the scheduling and priority changes.
// This implementation duplicates the libvirt parsing logic defined here:
// https://github.com/libvirt/libvirt/blob/56de80cb793aa7aedc45572f8b6ec3fc32c99309/src/util/virbitmap.c#L382
// except that in this case it uses a map[string]maskType instead of a bit array.
func parseCPUMask(mask string) (map[string]maskType, error) {

	if len(strings.TrimSpace(mask)) == 0 {
		return nil, fmt.Errorf("emtpy mask `%s`", mask)
	}

	vcpus := make(map[string]maskType)

	masks := strings.Split(mask, ",")
	for _, m := range masks {
		m = strings.TrimSpace(m)
		switch {
		case cpuRangeRegex.MatchString(m):
			match := cpuRangeRegex.FindSubmatch([]byte(m))
			startID, err := strconv.Atoi(string(match[1]))
			if err != nil {
				return nil, err
			}
			endID, err := strconv.Atoi(string(match[2]))
			if err != nil {
				return nil, err
			}
			if startID < 0 {
				return nil, fmt.Errorf("invalid vcpu mask start index `%d`", startID)
			}
			if endID < 0 {
				return nil, fmt.Errorf("invalid vcpu mask end index `%d`", endID)
			}
			if startID > endID {
				return nil, fmt.Errorf("invalid mask range `%d-%d`", startID, endID)
			}
			for id := startID; id <= endID; id++ {
				vid := strconv.Itoa(id)
				if _, ok := vcpus[vid]; !ok {
					vcpus[vid] = enabled
				}
			}
		case singleCPURegex.MatchString(m):
			match := singleCPURegex.FindSubmatch([]byte(m))
			vid, err := strconv.Atoi(string(match[1]))
			if err != nil {
				return nil, err
			}
			if vid < 0 {
				return nil, fmt.Errorf("invalid vcpu index `%d`", vid)
			}
			if _, ok := vcpus[string(match[1])]; !ok {
				vcpus[string(match[1])] = enabled
			}
		case negateCPURegex.MatchString(m):
			match := negateCPURegex.FindSubmatch([]byte(m))
			vid, err := strconv.Atoi(string(match[1]))
			if err != nil {
				return nil, err
			}
			if vid < 0 {
				return nil, fmt.Errorf("invalid vcpu index `%d`", vid)
			}
			vcpus[string(match[1])] = disabled
		default:
			return nil, fmt.Errorf("invalid mask value '%s' in '%s'", m, mask)
		}
	}
	// CPU 0 is used for housekeeping. Changes to the scheduling policy and priority don't apply.
	vcpus["0"] = disabled
	return vcpus, nil
}

func schedSetScheduler(pid int, p Policy, param SchedParam) error {
	_, _, e1 := unix.Syscall(unix.SYS_SCHED_SETSCHEDULER, uintptr(pid), uintptr(p), uintptr(unsafe.Pointer(&param)))
	if e1 != 0 {
		return syscall.Errno(e1)
	}
	return nil
}

func (d *VirtualMachineController) nonRootSetup(origVMI, vmi *v1.VirtualMachineInstance) error {
	res, err := d.podIsolationDetector.Detect(origVMI)
	if err != nil {
		return err
	}
	if err := d.prepareStorage(origVMI, res); err != nil {
		return err
	}
	if err := d.prepareTap(origVMI, res); err != nil {
		return err
	}
	if err := d.prepareVFIO(origVMI, res); err != nil {
		return err
	}
	if err := d.prepareVCPUSchedulerAndPriority(origVMI, res); err != nil {
		return err
	}
	return nil
}

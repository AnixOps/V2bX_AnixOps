package monitor

import (
	"os"
	"runtime"
	"time"

	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/disk"
	"github.com/shirou/gopsutil/v3/mem"
)

// SystemInfo 系统信息
type SystemInfo struct {
	CPUUsage    float64
	MemoryUsage float64
	DiskUsage   float64
	Uptime      int64
	OS          string
}

var startTime = time.Now()

// GetSystemInfo 获取系统信息
func GetSystemInfo() (*SystemInfo, error) {
	info := &SystemInfo{
		Uptime: int64(time.Since(startTime).Seconds()),
		OS:     runtime.GOOS + " " + runtime.GOARCH,
	}

	// CPU 使用率
	cpuPercent, err := cpu.Percent(time.Second, false)
	if err == nil && len(cpuPercent) > 0 {
		info.CPUUsage = cpuPercent[0]
	}

	// 内存使用率
	memInfo, err := mem.VirtualMemory()
	if err == nil {
		info.MemoryUsage = memInfo.UsedPercent
	}

	// 磁盘使用率 (根目录)
	diskPath := "/"
	if runtime.GOOS == "windows" {
		diskPath = "C:"
	}
	diskInfo, err := disk.Usage(diskPath)
	if err == nil {
		info.DiskUsage = diskInfo.UsedPercent
	}

	return info, nil
}

// GetHostname 获取主机名
func GetHostname() string {
	hostname, err := os.Hostname()
	if err != nil {
		return "unknown"
	}
	return hostname
}

// GetOSInfo 获取操作系统信息
func GetOSInfo() string {
	return runtime.GOOS + " " + runtime.GOARCH
}

// GetUptime 获取运行时间（秒）
func GetUptime() int64 {
	return int64(time.Since(startTime).Seconds())
}

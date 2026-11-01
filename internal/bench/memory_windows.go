//go:build windows

package bench

import (
	"math"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

type processMemoryCountersEx struct {
	CB                         uint32
	PageFaultCount             uint32
	PeakWorkingSetSize         uintptr
	WorkingSetSize             uintptr
	QuotaPeakPagedPoolUsage    uintptr
	QuotaPagedPoolUsage        uintptr
	QuotaPeakNonPagedPoolUsage uintptr
	QuotaNonPagedPoolUsage     uintptr
	PagefileUsage              uintptr
	PeakPagefileUsage          uintptr
	PrivateUsage               uintptr
}

var psapi = windows.NewLazySystemDLL("psapi.dll")
var getProcessMemoryInfo = psapi.NewProc("GetProcessMemoryInfo")

func currentRSSMB() float64 {
	var c processMemoryCountersEx
	c.CB = uint32(unsafe.Sizeof(c))
	h, err := windows.GetCurrentProcess()
	if err != nil {
		return 0
	}
	r, _, _ := getProcessMemoryInfo.Call(uintptr(h), uintptr(unsafe.Pointer(&c)), uintptr(c.CB))
	if r == 0 {
		return 0
	}
	return float64(c.WorkingSetSize) / (1024 * 1024)
}

func startPeakRSSSampling() func() *float64 {
	var max atomic.Uint64
	update := func() {
		v := currentRSSMB()
		bits := math.Float64bits(v)
		for old := max.Load(); bits > old && !max.CompareAndSwap(old, bits); old = max.Load() {
		}
	}
	update()
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(10 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				update()
			case <-stop:
				update()
				return
			}
		}
	}()
	var once sync.Once
	return func() *float64 {
		once.Do(func() { close(stop); <-done })
		v := math.Float64frombits(max.Load())
		if v == 0 {
			return nil
		}
		return &v
	}
}

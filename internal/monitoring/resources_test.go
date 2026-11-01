package monitoring

import (
	"testing"
	"time"
)

func resourceFixture(process, total, idle float64, resident, memory, available uint64) resourceReading {
	return resourceReading{processSeconds: &process, totalSeconds: &total, idleSeconds: &idle, residentBytes: &resident, memoryBytes: &memory, availableBytes: &available}
}

func TestResourceUsageMeasuresDeltasAndCachesFrequentPolls(t *testing.T) {
	var sampler resourceSampler
	now := time.Unix(1700000000, 0)
	first := sampler.snapshot(now, func() resourceReading { return resourceFixture(10, 100, 70, 100, 1000, 400) })
	if first.ProcessCPUPercent != nil || first.ServerCPUPercent != nil || *first.ServerMemoryUsedBytes != 600 || *first.ServerMemoryPercent != 60 {
		t.Fatalf("bad initial resource sample: %+v", first)
	}
	_ = sampler.snapshot(now.Add(time.Millisecond), func() resourceReading { t.Fatal("polled resources inside cache interval"); return resourceReading{} })
	next := sampler.snapshot(now.Add(2*time.Second), func() resourceReading { return resourceFixture(13, 108, 72, 120, 1000, 300) })
	if next.ProcessCPUPercent == nil || *next.ProcessCPUPercent != 150 || next.ServerCPUPercent == nil || *next.ServerCPUPercent != 75 || *next.ProcessResidentBytes != 120 || *next.ServerMemoryUsedBytes != 700 {
		t.Fatalf("CPU delta or RAM measurement incorrect: %+v", next)
	}
}

func TestUnavailableOrResetResourceCountersAreNotReportedAsUsage(t *testing.T) {
	var sampler resourceSampler
	now := time.Unix(1700000000, 0)
	_ = sampler.snapshot(now, func() resourceReading { return resourceFixture(10, 100, 70, 100, 1000, 400) })
	reset := sampler.snapshot(now.Add(time.Second), func() resourceReading { return resourceFixture(1, 1, 1, 100, 1000, 2000) })
	if reset.ProcessCPUPercent != nil || reset.ServerCPUPercent != nil || *reset.ServerMemoryPercent != 0 {
		t.Fatal("counter reset or excessive available RAM produced misleading usage")
	}
	missing := sampler.snapshot(now.Add(2*time.Second), func() resourceReading { return resourceReading{} })
	if missing.ProcessCPUPercent != nil || missing.ProcessResidentBytes != nil || missing.ServerMemoryBytes != nil {
		t.Fatal("unavailable resources retained a stale value")
	}
}

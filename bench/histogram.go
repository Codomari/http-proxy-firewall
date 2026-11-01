package main

import (
	"math"
	"math/bits"
	"time"
)

// 64 buckets per power of two bound storage and percentile rounding to 1.6%.
type histogram struct {
	buckets [64 * 64]uint64
	count   uint64
	sumNS   uint64
	maxNS   uint64
}

func (h *histogram) add(elapsed time.Duration) {
	ns := uint64(elapsed)
	if ns == 0 {
		ns = 1
	}
	exponent := bits.Len64(ns) - 1
	base := uint64(1) << exponent
	var subdivision uint64
	if exponent >= 6 {
		subdivision = (ns - base) >> (exponent - 6)
	} else {
		subdivision = (ns - base) * 64 / base
	}
	h.buckets[exponent*64+int(subdivision)]++
	h.count++
	h.sumNS += ns
	if ns > h.maxNS {
		h.maxNS = ns
	}
}

func (h *histogram) merge(other *histogram) {
	for i, count := range other.buckets {
		h.buckets[i] += count
	}
	h.count += other.count
	h.sumNS += other.sumNS
	if other.maxNS > h.maxNS {
		h.maxNS = other.maxNS
	}
}

func (h *histogram) percentile(percent float64) float64 {
	if h.count == 0 {
		return 0
	}
	target := uint64(math.Ceil(float64(h.count) * percent))
	var count uint64
	for i, n := range h.buckets {
		count += n
		if count >= target {
			upperNS := math.Ldexp(1, i/64) * (1 + float64(i%64+1)/64)
			return math.Min(upperNS, float64(h.maxNS)) / float64(time.Millisecond)
		}
	}
	return float64(h.maxNS) / float64(time.Millisecond)
}

type latencySummary struct {
	P50MS  float64 `json:"p50_ms"`
	P95MS  float64 `json:"p95_ms"`
	P99MS  float64 `json:"p99_ms"`
	MeanMS float64 `json:"mean_ms"`
	MaxMS  float64 `json:"max_ms"`
}

func (h *histogram) summary() latencySummary {
	mean := float64(0)
	if h.count > 0 {
		mean = float64(h.sumNS) / float64(h.count) / float64(time.Millisecond)
	}
	return latencySummary{P50MS: h.percentile(.5), P95MS: h.percentile(.95), P99MS: h.percentile(.99), MeanMS: mean, MaxMS: float64(h.maxNS) / float64(time.Millisecond)}
}

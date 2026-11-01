package firewall

import (
	"errors"
	"sync/atomic"
	"time"

	cve2026109618 "http-proxy-firewall/internal/firewall/cves/2026-109618"
	cve2026109619 "http-proxy-firewall/internal/firewall/cves/2026-109619"
)

type rejectionReason uint8

const (
	rejectionMalformed rejectionReason = iota
	rejectionBodyLimit
	rejectionInputLimit
	rejectionUploadProgress
	rejectionEncoding
	rejectionOverload
	rejectionBodyPolicy
	rejectionOther
	rejectionReasonCount
)

var rejectionReasonNames = [...]string{
	"malformed", "body_limit", "input_limit", "upload_progress",
	"encoding", "overload", "body_policy", "other",
}

type rejectionLogBucket struct {
	next       atomic.Int64
	suppressed atomic.Uint64
}

// Fixed reason buckets bound state regardless of attacker-controlled hosts,
// addresses or error strings. Suppressed requests perform only atomic work;
// no excerpts are built and no background workers are needed.
type rejectionSampler struct {
	interval time.Duration
	buckets  [rejectionReasonCount]rejectionLogBucket
}

func (s *rejectionSampler) allow(reason rejectionReason, now time.Time) (bool, uint64) {
	if s.interval == 0 {
		return true, 0
	}
	bucket := &s.buckets[reason]
	timestamp := now.UnixNano()
	for {
		next := bucket.next.Load()
		if next != 0 && timestamp < next {
			bucket.suppressed.Add(1)
			return false, 0
		}
		deadline := now.Add(s.interval).UnixNano()
		if deadline == 0 {
			deadline = 1 // Zero marks a bucket that has never emitted.
		}
		if bucket.next.CompareAndSwap(next, deadline) {
			return true, bucket.suppressed.Swap(0)
		}
	}
}

func reasonForRejection(status int, err error) rejectionReason {
	switch {
	case errors.Is(err, cve2026109618.ErrMalformed):
		return rejectionMalformed
	case errors.Is(err, cve2026109618.ErrBodyTooLarge):
		return rejectionBodyLimit
	case errors.Is(err, cve2026109618.ErrInputLimit):
		return rejectionInputLimit
	case errors.Is(err, cve2026109619.ErrUploadProgress):
		return rejectionUploadProgress
	case status == 415:
		return rejectionEncoding
	case status == 503:
		return rejectionOverload
	case status == 400:
		return rejectionBodyPolicy
	default:
		return rejectionOther
	}
}

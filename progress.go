package main

import (
	"sync/atomic"
	"time"
)

// ProgressStats holds progress metrics
type ProgressStats struct {
	Processed int64
	Success   int64
	Total     int64
	Elapsed   time.Duration
}

// Progress tracks scan/test progress with atomic counters
type Progress struct {
	total     int64
	processed int64
	success   int64
	startTime time.Time
	enabled   bool
}

func NewProgress(total int, enabled bool) *Progress {
	return &Progress{
		total:     int64(total),
		startTime: time.Now(),
		enabled:   enabled,
	}
}

func (p *Progress) Increment() {
	atomic.AddInt64(&p.processed, 1)
}

func (p *Progress) Success() {
	atomic.AddInt64(&p.success, 1)
}

func (p *Progress) Stats() ProgressStats {
	return ProgressStats{
		Processed: atomic.LoadInt64(&p.processed),
		Success:   atomic.LoadInt64(&p.success),
		Total:     p.total,
		Elapsed:   time.Since(p.startTime),
	}
}

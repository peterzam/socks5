package bandwidth

import (
	"math"
	"sync"
)

// Inf infinite rate
const Inf = math.MaxInt64

// BandwidthConfig holds the limiter configuration limit and burst values.
type BandwidthConfig struct {
	rwLock sync.RWMutex
	// limit is the overall bytes per second rate
	limit int64
	// buts is the number of bytes that can be consumed in a single Read call
	burst int64
}

// SetLimit sets the overall bytes per second rate
func (conf *BandwidthConfig) SetLimit(limit int64) {
	conf.rwLock.Lock()
	defer conf.rwLock.Unlock()

	conf.limit = limit
}

// SetBurst sets the number of bytes that can be consumed in a single Read call
func (conf *BandwidthConfig) SetBurst(burst int64) {
	conf.rwLock.Lock()
	defer conf.rwLock.Unlock()

	conf.burst = validateBurst(burst, conf.limit)
}

// Limit returns the limit in bytes per second.
func (conf *BandwidthConfig) GetLimit() int64 {
	conf.rwLock.RLock()
	defer conf.rwLock.RUnlock()

	return conf.limit
}

// Burst returns the burst in bytes per second.
func (conf *BandwidthConfig) GetBurst() int64 {
	conf.rwLock.RLock()
	defer conf.rwLock.RUnlock()

	return conf.burst
}

func validateBurst(burst int64, limit int64) int64 {
	if burst <= 0 {
		burst = int64(limit)
	}

	return burst
}

func validateLimit(limit int64) int64 {
	if limit < 1 {
		return Inf
	}

	return limit
}

// NewBandwidthConfig contains the over limit in bytes per second and the burst; maximum bytes that can be read in a single call.
// The BandwidthConfig instance that can be read and updated from multiple go routines.
func NewBandwidthConfig(limit int64, burst int64) *BandwidthConfig {

	vLimit := validateLimit(limit)
	return &BandwidthConfig{
		limit: vLimit,
		burst: validateBurst(burst, vLimit),
	}
}

package bandwidth

import (
	"context"
	"net"
)

type bandwidthLimitedConnWrapper struct {
	net.Conn
	writeLimiter BandwidthLimiter
	readLimiter  BandwidthLimiter

	ctx context.Context
}

// Read data from a connection. The reads are rate limited at bytes per second.
// len(b) must be bigger than the burst size set on the limiter, otherwise an error is returned.
func (c *bandwidthLimitedConnWrapper) Read(b []byte) (int, error) {
	err := c.readLimiter.WaitN(c.ctx, int64(len(b)))
	if err != nil {
		return 0, err
	}

	return c.Conn.Read(b)
}

// Write data to a connection. The writes are rate limited at bytes per second.
// len(b) must be bigger than the burst size set on the limiter, otherwise an error is returned.
func (c *bandwidthLimitedConnWrapper) Write(b []byte) (int, error) {
	err := c.writeLimiter.WaitN(c.ctx, int64(len(b)))
	if err != nil {
		return 0, err
	}

	return c.Conn.Write(b)
}

// NewBandwidthLimitedConn returns a net.Conn that has its Read method rate limited
// by the limiter.
func NewBandwidthLimitedConn(ctx context.Context, readLimiter BandwidthLimiter, writeLimiter BandwidthLimiter, conn net.Conn) net.Conn {
	return &bandwidthLimitedConnWrapper{
		Conn:         conn,
		ctx:          ctx,
		readLimiter:  readLimiter,
		writeLimiter: writeLimiter,
	}
}

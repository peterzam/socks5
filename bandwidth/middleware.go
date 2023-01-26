package bandwidth

import (
	"context"
	"net"
)

// ListenerConfig groups together the configuration for a Listener and the limiters that should be used.
type ListenerConfig struct {

	// ReadServerRate the global server read limit and burst config
	ReadServerRate *BandwidthConfig

	// WriteServerRate the global server write limit and burst config
	WriteServerRate *BandwidthConfig

	// ReadConnRate the per connection read limit and burst config
	ReadConnRate *BandwidthConfig

	// WriteConnRate the per connection write limit and burst config
	WriteConnRate *BandwidthConfig
}

// NewListenerConfig is a helper function to create a ListenerConfig from a single BandwidthConfig.
// the ReadServerRate, WriterServerRate, ReadConnRate, and WriteConnRate are all set to the BandwidthConfig.
func NewListenerConfig(BandwidthConfig *BandwidthConfig) *ListenerConfig {
	return &ListenerConfig{
		ReadServerRate:  BandwidthConfig,
		WriteServerRate: BandwidthConfig,
		ReadConnRate:    BandwidthConfig,
		WriteConnRate:   BandwidthConfig,
	}
}

func NeweSimpleListenerConfig(read, write int64) *ListenerConfig {
	return &ListenerConfig{
		ReadServerRate:  NewBandwidthConfig(read, read),
		WriteServerRate: NewBandwidthConfig(write, write),
		ReadConnRate:    NewBandwidthConfig(read, read),
		WriteConnRate:   NewBandwidthConfig(write, write),
	}
}

type rateListWrapper struct {
	net.Listener

	serverReadLimiter  BandwidthLimiter
	serverWriteLimiter BandwidthLimiter

	listenerConfig *ListenerConfig

	ctx context.Context
}

// Accept returns a new connection or error.
// The new connection is rate limited, configured by the connection rate limits and the parent serverLimiter
func (w *rateListWrapper) Accept() (net.Conn, error) {

	conn, err := w.Listener.Accept()
	if err != nil {
		return nil, err
	}

	readLimiter := w.serverReadLimiter.Child(w.listenerConfig.ReadConnRate)
	writeLimiter := w.serverWriteLimiter.Child(w.listenerConfig.WriteConnRate)

	// The child will check its connection rate limits and also the overall serverLimiter
	return NewBandwidthLimitedConn(w.ctx, readLimiter, writeLimiter, conn), err
}

// NewListener returns a net.Listener that will apply rate limits to each connection and also globally for all connections
// via the listenerConfig.ReadServerRate and listenerConfig.WriteServerRate configs.
func NewListener(ctx context.Context, listenerConfig *ListenerConfig, listener net.Listener) net.Listener {

	return &rateListWrapper{
		Listener: listener,

		serverReadLimiter:  NewBandwidthLimiter(listenerConfig.ReadServerRate),
		serverWriteLimiter: NewBandwidthLimiter(listenerConfig.WriteServerRate),

		listenerConfig: listenerConfig,

		ctx: ctx,
	}
}

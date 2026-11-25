package daemon

import (
	"context"
	"errors"
	"os"

	C "github.com/sagernet/sing-box/constant"
	N "github.com/sagernet/sing/common/network"
)

// ServiceRecoveryTransport captures one running WireGuard endpoint and its
// lifetime. A stop or reload cancels consumers; no default outbound is used.
func (s *StartedService) ServiceRecoveryTransport(tag string) (context.Context, N.Dialer, error) {
	s.serviceAccess.RLock()
	defer s.serviceAccess.RUnlock()
	if s.closed || s.serviceStatus.Status != ServiceStatus_STARTED || s.instance == nil {
		return nil, nil, os.ErrClosed
	}
	endpoint, found := s.instance.endpointManager.Get(tag)
	if !found || endpoint.Type() != C.TypeWireGuard {
		return nil, nil, errors.New("recovery WireGuard endpoint unavailable")
	}
	return s.instance.ctx, endpoint, nil
}

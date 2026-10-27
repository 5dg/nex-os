package trust

import (
	"context"
	"google.golang.org/grpc/credentials"
)

type perRPC struct {
	config *Config
	peer   Role
}

func (p perRPC) RequireTransportSecurity() bool { return true }
func (p perRPC) GetRequestMetadata(ctx context.Context, _ ...string) (map[string]string, error) {
	info, ok := credentials.RequestInfoFromContext(ctx)
	if !ok {
		return nil, ErrIdentity
	}
	tlsInfo, ok := info.AuthInfo.(credentials.TLSInfo)
	if !ok {
		return nil, ErrIdentity
	}
	if e := p.config.CheckPeer(&tlsInfo.State, []Role{p.peer}); e != nil {
		return nil, e
	}
	return map[string]string{}, nil
}
func (c *Config) PerRPCCredentials(peer Role) credentials.PerRPCCredentials { return perRPC{c, peer} }

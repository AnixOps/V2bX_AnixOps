//go:build linux

package gostmesh

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
)

type tunnelTCPProber struct{}

func newSystemProber() Prober {
	return tunnelTCPProber{}
}

func (tunnelTCPProber) Probe(ctx context.Context, tunnel Tunnel) error {
	host, port, err := net.SplitHostPort(tunnel.Health.Target)
	if err != nil {
		return err
	}
	addresses, err := net.DefaultResolver.LookupNetIP(ctx, "ip4", host)
	if err != nil {
		return fmt.Errorf("resolve tunnel %q health target: %w", tunnel.ID, err)
	}
	sourceAddress := net.ParseIP(tunnel.Health.SourceAddress)
	if sourceAddress == nil {
		return errors.New("health source address is invalid")
	}
	dialer := net.Dialer{LocalAddr: &net.TCPAddr{IP: sourceAddress}}
	var probeErr error
	for _, address := range addresses {
		address = address.Unmap()
		if err := validProbeAddress(address); err != nil {
			probeErr = errors.Join(probeErr, err)
			continue
		}
		connection, err := dialer.DialContext(ctx, "tcp4", net.JoinHostPort(address.String(), port))
		if err != nil {
			probeErr = errors.Join(probeErr, err)
			continue
		}
		if err := connection.Close(); err != nil {
			probeErr = errors.Join(probeErr, err)
			continue
		}
		return nil
	}
	if probeErr == nil {
		probeErr = errors.New("target has no usable IPv4 address")
	}
	return fmt.Errorf("probe tunnel %q health target: %w", tunnel.ID, probeErr)
}

func validProbeAddress(address netip.Addr) error {
	if !address.IsValid() || !address.Is4() || address.IsUnspecified() || address.IsLoopback() || address.IsMulticast() || address.IsLinkLocalUnicast() {
		return fmt.Errorf("health probe address %s is not a usable IPv4 unicast address", address)
	}
	return nil
}

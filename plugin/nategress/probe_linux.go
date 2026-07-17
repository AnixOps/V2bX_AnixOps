//go:build linux

package nategress

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"syscall"

	"golang.org/x/sys/unix"
)

type markedTCPProber struct{}

func newSystemProber() Prober {
	return markedTCPProber{}
}

func (markedTCPProber) Probe(ctx context.Context, config Config) error {
	host, port, err := net.SplitHostPort(config.HealthCheckTarget)
	if err != nil {
		return err
	}
	var probeErr error
	for _, family := range enabledFamilies(config) {
		network := "tcp4"
		lookupNetwork := "ip4"
		if family == IPv6 {
			network = "tcp6"
			lookupNetwork = "ip6"
		}
		dialer := net.Dialer{
			Control: func(_, _ string, connection syscall.RawConn) error {
				var socketErr error
				if err := connection.Control(func(fd uintptr) {
					if err := unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, config.DefaultMark); err != nil {
						socketErr = fmt.Errorf("set health probe SO_MARK: %w", err)
						return
					}
					if err := unix.SetsockoptString(int(fd), unix.SOL_SOCKET, unix.SO_BINDTODEVICE, config.EgressInterface); err != nil {
						socketErr = fmt.Errorf("bind health probe to egress interface: %w", err)
					}
				}); err != nil {
					return err
				}
				return socketErr
			},
		}
		addresses, err := net.DefaultResolver.LookupNetIP(ctx, lookupNetwork, host)
		if err != nil {
			probeErr = errors.Join(probeErr, fmt.Errorf("resolve %s egress target: %w", familyName(family), err))
			continue
		}
		var familyErr error
		connected := false
		for _, address := range addresses {
			if err := validateProbeAddress(address); err != nil {
				familyErr = errors.Join(familyErr, err)
				continue
			}
			connection, err := dialer.DialContext(ctx, network, net.JoinHostPort(address.String(), port))
			if err != nil {
				familyErr = errors.Join(familyErr, err)
				continue
			}
			if err := connection.Close(); err != nil {
				familyErr = errors.Join(familyErr, err)
				continue
			}
			connected = true
			break
		}
		if !connected {
			if familyErr == nil {
				familyErr = errors.New("target has no usable addresses")
			}
			probeErr = errors.Join(probeErr, fmt.Errorf("probe %s egress target: %w", familyName(family), familyErr))
		}
	}
	return probeErr
}

func validateProbeAddress(address netip.Addr) error {
	if !address.IsValid() || address.IsUnspecified() || address.IsLoopback() || address.IsMulticast() || address.IsLinkLocalUnicast() {
		return fmt.Errorf("health probe address %s is not an external unicast address", address)
	}
	return nil
}

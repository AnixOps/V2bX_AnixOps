package gostmesh

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

type CommandSpec struct {
	TunnelID string
	Binary   string
	Args     []string
}

func BuildCommandSpecs(config Config, gostBinary string) ([]CommandSpec, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	gostBinary = strings.TrimSpace(gostBinary)
	if gostBinary == "" || strings.ContainsAny(gostBinary, "\x00\r\n") {
		return nil, errors.New("GOST binary is invalid")
	}

	commands := make([]CommandSpec, 0, len(config.Tunnels))
	for _, tunnel := range config.Tunnels {
		listener, err := tunListenerURL(tunnel)
		if err != nil {
			return nil, fmt.Errorf("tunnel %q: %w", tunnel.ID, err)
		}
		relay, err := relayURL(tunnel)
		if err != nil {
			return nil, fmt.Errorf("tunnel %q: %w", tunnel.ID, err)
		}
		args := []string{"-L", listener}
		if tunnel.Role == "entry" {
			args = append(args, "-F", relay)
		} else {
			args = append(args, "-L", relay)
		}
		commands = append(commands, CommandSpec{
			TunnelID: tunnel.ID,
			Binary:   gostBinary,
			Args:     args,
		})
	}
	return commands, nil
}

func tunListenerURL(tunnel Tunnel) (string, error) {
	query := url.Values{}
	query.Set("mtu", strconv.Itoa(tunnel.TUN.MTU))
	query.Set("name", tunnel.TUN.Name)
	query.Set("net", tunnel.TUN.Address)
	query.Set("peer", tunnel.TUN.Peer)

	endpoint := &url.URL{Scheme: "tun"}
	if tunnel.Role == "entry" {
		endpoint.Host = ":0"
		endpoint.Path = "/:" + strconv.Itoa(tunnel.TUN.Port)
	} else {
		endpoint.Host = ":" + strconv.Itoa(tunnel.TUN.Port)
		query.Set("gw", tunnel.TUN.Peer)
		query.Set("route", strings.Join(tunnel.Routing.RouteCIDRs, ","))
	}
	endpoint.RawQuery = query.Encode()
	return endpoint.String(), nil
}

func relayURL(tunnel Tunnel) (string, error) {
	scheme := "relay+" + tunnel.Transport
	endpoint := &url.URL{Scheme: scheme}
	query := url.Values{}
	if tunnel.Role == "entry" {
		endpoint.Host = net.JoinHostPort(tunnel.Remote.Address, strconv.Itoa(tunnel.Remote.Port))
		query.Set("secure", "true")
		query.Set("caFile", tunnel.TLS.CAFile)
		query.Set("certFile", tunnel.TLS.CertFile)
		query.Set("keyFile", tunnel.TLS.KeyFile)
		query.Set("serverName", tunnel.TLS.ServerName)
	} else {
		endpoint.Host = net.JoinHostPort(tunnel.Listen.Address, strconv.Itoa(tunnel.Listen.Port))
		query.Set("bind", "true")
		query.Set("caFile", tunnel.TLS.CAFile)
		query.Set("certFile", tunnel.TLS.CertFile)
		query.Set("keyFile", tunnel.TLS.KeyFile)
	}
	if tunnel.Transport == "wss" {
		query.Set("path", tunnel.WSSPath)
	}
	endpoint.RawQuery = query.Encode()
	return endpoint.String(), nil
}

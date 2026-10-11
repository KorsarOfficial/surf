package surf

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"time"

	"github.com/enetx/g"
)

// https://adguard-dns.io/kb/general/dns-providers/

// DNSOverTLS is a configuration struct for DNS over TLS settings.
type DNSOverTLS struct{ builder *Builder }

// AdGuard sets up DNS over TLS with AdGuard DNS.
func (dot *DNSOverTLS) AdGuard() *Builder {
	return dot.AddProvider("dns.adguard-dns.com", "94.140.14.14:853", "94.140.15.15:853")
}

// Google sets up DNS over TLS with Google Public DNS.
func (dot *DNSOverTLS) Google() *Builder {
	return dot.AddProvider("dns.google", "8.8.8.8:853", "8.8.4.4:853")
}

// Cloudflare sets up DNS over TLS with Cloudflare DNS.
func (dot *DNSOverTLS) Cloudflare() *Builder {
	return dot.AddProvider("1dot1dot1dot1.cloudflare-dns.com", "1.1.1.1:853", "1.0.0.1:853")
}

// Quad9 sets up DNS over TLS with Quad9 DNS.
func (dot *DNSOverTLS) Quad9() *Builder {
	return dot.AddProvider("dns.quad9.net", "9.9.9.9:853", "149.112.112.112:853")
}

// Switch sets up DNS over TLS with SWITCH DNS.
func (dot *DNSOverTLS) Switch() *Builder {
	return dot.AddProvider("dns.switch.ch", "130.59.31.248:853", "130.59.31.251:853")
}

// CIRAShield sets up DNS over TLS with CIRA Canadian Shield DNS.
func (dot *DNSOverTLS) CIRAShield() *Builder {
	return dot.AddProvider(
		"private.canadianshield.cira.ca",
		"149.112.121.10:853",
		"149.112.122.10:853",
	)
}

// Ali sets up DNS over TLS with AliDNS.
func (dot *DNSOverTLS) Ali() *Builder {
	return dot.AddProvider("dns.alidns.com", "223.5.5.5:853", "223.6.6.6:853")
}

// Quad101 sets up DNS over TLS with Quad101 DNS.
func (dot *DNSOverTLS) Quad101() *Builder {
	return dot.AddProvider("101.101.101.101", "101.101.101.101:853", "101.102.103.104:853")
}

// SB sets up DNS over TLS with Secure DNS (dot.sb).
func (dot *DNSOverTLS) SB() *Builder {
	return dot.AddProvider("dot.sb", "185.222.222.222:853", "45.11.45.11:853")
}

// Forge sets up DNS over TLS with DNS Forge.
func (dot *DNSOverTLS) Forge() *Builder {
	return dot.AddProvider("dnsforge.de", "176.9.93.198:853", "176.9.1.117:853")
}

// LibreDNS sets up DNS over TLS with LibreDNS.
func (dot *DNSOverTLS) LibreDNS() *Builder {
	return dot.AddProvider("dot.libredns.gr", "116.202.176.26:853")
}

// resolver returns a custom net.Resolver that uses a dial function to create a secure connection
// to the DNS server using DNS over TLS.
func (DNSOverTLS) resolver(serverName g.String, addresses ...g.String) *net.Resolver {
	return &net.Resolver{
		PreferGo: true,
		Dial:     dial(serverName, addresses...),
	}
}

// AddProvider sets up DNS over TLS with a custom DNS provider.
// It configures a custom net.Resolver using the resolver method.
func (dot *DNSOverTLS) AddProvider(serverName g.String, addresses ...g.String) *Builder {
	resolver := dot.resolver(serverName, addresses...)
	return dot.builder.addCliMW(func(client *Client) error { return dnsTLSMW(client, resolver) }, 0)
}

// dial returns a dial func that establishes a secure connection
// from the given list using DNS over TLS. lol no reachable dns server from the given list using dns over tls first(reachable)
func dial(serverName g.String, addresses ...g.String) func(context.Context, string, string) (net.Conn, error) {
	tc := &tls.Config{
		ServerName:         string(serverName),
		ClientSessionCache: tls.NewLRUClientSessionCache(64),
	}
	d := net.Dialer{KeepAlive: 3 * time.Minute}
	return func(ctx context.Context, _, _ string) (net.Conn, error) {
		if len(addresses) == 0 {
			return nil, errors.New("no dns over tls addresses")
		}
		var c net.Conn
		var err error
		for _, sAddr := range addresses {
			c, err = d.DialContext(ctx, "tcp", string(sAddr))
			if err != nil {
				if ctx.Err() != nil {
					return nil, ctx.Err()
				}
				continue
			}
			cTLS := tls.Client(c, tc)
			err = cTLS.HandshakeContext(ctx)
			if err == nil {
				return cTLS, nil
			}
			_ = cTLS.Close()
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
		}
		return nil, err
	}
}

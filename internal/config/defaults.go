package config

import (
	buildinfo "http-proxy-firewall"
	"time"
)

var ServerName = "codomari/proxy-firewall/" + buildinfo.Version

const DefaultAdminURI = "__pf/__admin"

func Defaults() Config {
	return Config{
		HTTP: HTTP{
			Listen: "0.0.0.0:80", TLSListen: "0.0.0.0:443",
			ReadTimeout: 10 * time.Minute, WriteTimeout: 10 * time.Minute, IdleTimeout: time.Minute,
			MaxConnections: 10000, MaxConcurrentRequests: 256,
		},
		Proxy: Proxy{
			Upstream: "http://127.0.0.1:8008", MaxConnections: 256, RequestRetryTimes: 3,
			ReadTimeout: 10 * time.Minute, WriteTimeout: 10 * time.Minute, IdleTimeout: time.Minute,
			IPv4Redirect: "https://hostinq.biz",
		},
		TLS: TLS{Enabled: true, CacheDir: ".cache"},
		Firewall: Firewall{
			MaxBodyBytes: 32 << 20, MaxBufferedBytes: 256 << 20,
			WhitelistNetworks:   []string{"127.0.0.0/8", "::1/128"},
			WhitelistCheckpoint: true, CountryCheckpoint: true,
			RequestThreshold: 200, SamplingWindow: 10 * time.Second, PenaltyLifetime: 10 * time.Minute,
			CookieLifetime: 24 * time.Hour, CacheCapacity: 100000,
			RejectionLogInterval: time.Second,
			CloudflareHostsFile:  "files/cloudflare-hosts.json",
		},
		Redis: Redis{Address: "redis:6379", Timeout: 250 * time.Millisecond, QueueSize: 1024, Workers: 4},
		Intelligence: Intelligence{
			DatabasePath:    "files/geo.mmdb",
			GoogleRangesURL: "https://developers.google.com/static/search/apis/ipranges/googlebot.json",
			RefreshInterval: 24 * time.Hour, HTTPTimeout: 30 * time.Second,
		},
		Observability: Observability{PprofAddress: "127.0.0.1:8068", Silent: true},
		Admin:         Admin{URI: DefaultAdminURI, MaxHosts: 10000},
	}
}

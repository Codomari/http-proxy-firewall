package config

import "time"

// Config is immutable after startup. Each section belongs to one component.
type Config struct {
	HTTP          HTTP
	Proxy         Proxy
	TLS           TLS
	Firewall      Firewall
	Redis         Redis
	Intelligence  Intelligence
	Observability Observability
	Admin         Admin
}

type HTTP struct {
	Listen                string
	TLSListen             string
	ReadTimeout           time.Duration
	WriteTimeout          time.Duration
	IdleTimeout           time.Duration
	MaxConnections        int
	MaxConcurrentRequests int
}

type Proxy struct {
	Upstream       string
	Routes         map[string]string
	MaxConnections int
	ReadTimeout    time.Duration
	WriteTimeout   time.Duration
	IdleTimeout    time.Duration
	IPv4Redirect   string
}

type TLS struct {
	Enabled            bool
	Email              string
	CacheDir           string
	Hosts              []string
	AllowLegacyClients bool
	CertificateFile    string
	PrivateKeyFile     string
}

type Firewall struct {
	MaxBodyBytes          int64
	MaxBufferedBytes      int64
	WhitelistIPs          []string
	WhitelistNetworks     []string
	AllowedCountries      []string
	TrustedProxies        []string
	TrustCloudflareHeader bool
	RequestThreshold      uint64
	SamplingWindow        time.Duration
	PenaltyLifetime       time.Duration
	CookieLifetime        time.Duration
	CacheCapacity         int
	UploadProgressNames   []string
	RejectionLogInterval  time.Duration
}

type Redis struct {
	Enabled   bool
	Address   string
	Password  string
	DB        int
	Timeout   time.Duration
	QueueSize int
	Workers   int
}

type Intelligence struct {
	DatabasePath      string
	MaxMindLicenseKey string
	GoogleRangesURL   string
	RefreshInterval   time.Duration
	HTTPTimeout       time.Duration
}

type Observability struct {
	Metrics      bool
	PprofAddress string
	Silent       bool
}

type Admin struct {
	URI             string
	CredentialsFile string
	Enabled         bool
	User            string
	Password        string
	MaxHosts        int
}

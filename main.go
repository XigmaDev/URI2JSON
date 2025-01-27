package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/url"
	"strings"
	"time"

	tele "gopkg.in/telebot.v4"
)

type Config struct {
	Protocol      string
	UUID          string
	Address       string
	Port          string
	Type          string
	Path          string
	Host          string
	Mode          string
	Security      string
	Fingerprint   string
	ALPN          string
	AllowInsecure string
	SNI           string
	Fragment      string
	Password      string
	Method        string
	Remark        string
}

// XrayConfig
type XrayConfig struct {
	Inbounds  []Inbound  `json:"inbounds"`
	Outbounds []Outbound `json:"outbounds"`
}

type Inbound struct {
	Port          int      `json:"port"`
	Protocol      string   `json:"protocol"`
	Settings      Settings `json:"settings"`
	Tag           string   `json:"tag"`
	Type          string   `json:"type"`
	Inet4_address string   `json:"inet4_address"`
	Auto_route    bool     `json:"auto_route"`
	Strict_route  bool     `json:"strict_route"`
}

type Settings struct {
	Auth string `json:"auth"`
	UDP  bool   `json:"udp"`
}

type Outbound struct {
	Protocol       string         `json:"protocol"`
	Settings       interface{}    `json:"settings"`
	StreamSettings StreamSettings `json:"streamSettings"`
	Tag            string         `json:"tag"`
}

type VNextSettings struct {
	VNext []VNext `json:"vnext"`
}

type VNext struct {
	Address string `json:"address"`
	Port    int    `json:"port"`
	Users   []User `json:"users"`
}

type User struct {
	ID         string `json:"id"`
	Encryption string `json:"encryption"`
	Level      int    `json:"level"`
}

type ShadowsocksSettings struct {
	Servers []ShadowsocksServer `json:"servers"`
}

type ShadowsocksServer struct {
	Address  string `json:"address"`
	Port     int    `json:"port"`
	Method   string `json:"method"`
	Password string `json:"password"`
}

type TrojanSettings struct {
	Servers []TrojanServer `json:"servers"`
}

type TrojanServer struct {
	Address  string `json:"address"`
	Port     int    `json:"port"`
	Password string `json:"password"`
}

type StreamSettings struct {
	Network     string      `json:"network"`
	Security    string      `json:"security"`
	TLSSettings TLSSettings `json:"tlsSettings"`
	TCPSettings TCPSettings `json:"tcpSettings"`
}

type TLSSettings struct {
	ServerName    string   `json:"serverName"`
	Fingerprint   string   `json:"fingerprint"`
	ALPN          []string `json:"alpn"`
	AllowInsecure bool     `json:"allowInsecure"`
}

type TCPSettings struct {
	Header Header `json:"header"`
}

type Header struct {
	Type    string  `json:"type"`
	Request Request `json:"request"`
}

type Request struct {
	Path    []string            `json:"path"`
	Headers map[string][]string `json:"headers"`
}

// SingboxConfig
type SingboxConfig struct {
	Dns       []string          `json:"dns"`
	Log       Log               `json:"log"`
	Inbounds  []Inbound         `json:"inbounds"`
	Outbounds []OutboundSingbox `json:"outbounds"`
}

type Log struct {
	Level string `json:"level"`
}

type OutboundSingbox struct {
	Type       string      `json:"type"`
	Tag        string      `json:"tag"`
	Server     string      `json:"server"`
	ServerPort int         `json:"server_port"`
	Settings   interface{} `json:"settings"`
	TLS        TLS         `json:"tls"`
	Transport  Transport   `json:"transport"`
}

type TLS struct {
	Enabled     bool     `json:"enabled"`
	ServerName  string   `json:"server_name"`
	ALPN        []string `json:"alpn"`
	Fingerprint string   `json:"fingerprint"`
	Insecure    bool     `json:"insecure"`
}

type Transport struct {
	Type string `json:"type"`
	Host string `json:"host"`
	Path string `json:"path"`
}

func parseURI(uri string) (*Config, error) {
	var ruri string
	if strings.HasPrefix(uri, "vmess://") {
		decoded, err := base64.StdEncoding.DecodeString(uri[8:])
		if err != nil {
			return nil, fmt.Errorf("failed to decode Base64: %v", err)
		}
		ruri = string(decoded)
	} else {
		ruri = uri
	}
	parsedURL, err := url.Parse(ruri)
	if err != nil {
		return nil, fmt.Errorf("failed to parse URI: %v", err)
	}

	config := &Config{
		Protocol: parsedURL.Scheme,
		Address:  parsedURL.Hostname(),
		Port:     parsedURL.Port(),
		Fragment: parsedURL.Fragment,
	}

	switch config.Protocol {
	case "vless", "vmess":
		userInfo := parsedURL.User
		config.UUID = userInfo.Username()
		queryParams := parsedURL.Query()
		config.Type = queryParams.Get("type")
		config.Path = queryParams.Get("path")
		config.Host = queryParams.Get("host")
		config.Mode = queryParams.Get("mode")
		config.Security = queryParams.Get("security")
		config.Fingerprint = queryParams.Get("fp")
		config.ALPN = queryParams.Get("alpn")
		config.AllowInsecure = queryParams.Get("allowInsecure")
		config.SNI = queryParams.Get("sni")
	case "ss":
		userInfo := parsedURL.User
		decoded, err := base64.RawURLEncoding.DecodeString(userInfo.Username())
		if err != nil {
			return nil, fmt.Errorf("failed to decode Shadowsocks password: %v", err)
		}
		parts := strings.Split(string(decoded), ":")
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid Shadowsocks URI format")
		}
		config.Method = parts[0]
		config.Password = parts[1]
	case "trojan":
		config.Password = parsedURL.User.Username()
	default:
		return nil, fmt.Errorf("unsupported protocol: %s", config.Protocol)
	}

	return config, nil
}

func generateXrayConfig(config *Config) ([]byte, error) {
	xrayConfig := XrayConfig{
		Inbounds: []Inbound{
			{
				Port:     1080,
				Protocol: "socks",
				Settings: Settings{
					Auth: "noauth",
					UDP:  true,
				},
				Tag: "socks-inbound",
			},
		},
	}

	var outbound Outbound
	switch config.Protocol {
	case "vless", "vmess":
		outbound = Outbound{
			Protocol: config.Protocol,
			Settings: VNextSettings{
				VNext: []VNext{
					{
						Address: config.Address,
						Port:    8443,
						Users: []User{
							{
								ID:         config.UUID,
								Encryption: "none",
								Level:      0,
							},
						},
					},
				},
			},
			StreamSettings: StreamSettings{
				Network:  "tcp",
				Security: "tls",
				TLSSettings: TLSSettings{
					ServerName:    config.SNI,
					Fingerprint:   config.Fingerprint,
					ALPN:          []string{"h3", "h2", "http/1.1"},
					AllowInsecure: config.AllowInsecure == "1",
				},
				TCPSettings: TCPSettings{
					Header: Header{
						Type: "http",
						Request: Request{
							Path: []string{config.Path},
							Headers: map[string][]string{
								"Host": {config.Host},
							},
						},
					},
				},
			},
			Tag: fmt.Sprintf("%s-outbound", config.Protocol),
		}
	case "ss":
		outbound = Outbound{
			Protocol: "shadowsocks",
			Settings: ShadowsocksSettings{
				Servers: []ShadowsocksServer{
					{
						Address:  config.Address,
						Port:     8443,
						Method:   config.Method,
						Password: config.Password,
					},
				},
			},
			Tag: "shadowsocks-outbound",
		}
	case "trojan":
		outbound = Outbound{
			Protocol: "trojan",
			Settings: TrojanSettings{
				Servers: []TrojanServer{
					{
						Address:  config.Address,
						Port:     8443,
						Password: config.Password,
					},
				},
			},
			Tag: "trojan-outbound",
		}
	default:
		return nil, fmt.Errorf("unsupported protocol: %s", config.Protocol)
	}

	xrayConfig.Outbounds = []Outbound{outbound}
	return json.MarshalIndent(xrayConfig, "", "  ")
}

func generateSingboxConfig(config *Config) ([]byte, error) {
	singboxConfig := SingboxConfig{
		Log: Log{
			Level: "info",
		},
		Inbounds: []Inbound{
			{
				Port:     1080,
				Protocol: "socks",
				Settings: Settings{
					Auth: "noauth",
					UDP:  true,
				},
				Tag: "socks-inbound",
			},
		},
	}

	var outbound OutboundSingbox
	switch config.Protocol {
	case "vless", "vmess":
		outbound = OutboundSingbox{
			Type:       config.Protocol,
			Tag:        fmt.Sprintf("%s-outbound", config.Protocol),
			Server:     config.Address,
			ServerPort: 8443,
			Settings: map[string]interface{}{
				"vnext": []map[string]interface{}{
					{
						"address": config.Address,
						"port":    8443,
						"users": []map[string]interface{}{
							{
								"id":         config.UUID,
								"encryption": "none",
								"level":      0,
							},
						},
					},
				},
			},
			TLS: TLS{
				Enabled:     true,
				ServerName:  config.SNI,
				ALPN:        []string{"h3", "h2", "http/1.1"},
				Fingerprint: config.Fingerprint,
				Insecure:    config.AllowInsecure == "1",
			},
			Transport: Transport{
				Type: "http",
				Host: config.Host,
				Path: config.Path,
			},
		}
	case "ss":
		outbound = OutboundSingbox{
			Type:       "shadowsocks",
			Tag:        "shadowsocks-outbound",
			Server:     config.Address,
			ServerPort: 8443,
			Settings: map[string]interface{}{
				"servers": []map[string]interface{}{
					{
						"address":  config.Address,
						"port":     8443,
						"method":   config.Method,
						"password": config.Password,
					},
				},
			},
		}
	case "trojan":
		outbound = OutboundSingbox{
			Type:       "trojan",
			Tag:        "trojan-outbound",
			Server:     config.Address,
			ServerPort: 8443,
			Settings: map[string]interface{}{
				"servers": []map[string]interface{}{
					{
						"address":  config.Address,
						"port":     8443,
						"password": config.Password,
					},
				},
			},
			TLS: TLS{
				Enabled:     true,
				ServerName:  config.SNI,
				ALPN:        []string{"h3", "h2", "http/1.1"},
				Fingerprint: config.Fingerprint,
				Insecure:    config.AllowInsecure == "1",
			},
		}
	default:
		return nil, fmt.Errorf("unsupported protocol: %s", config.Protocol)
	}

	singboxConfig.Outbounds = []OutboundSingbox{outbound}
	return json.MarshalIndent(singboxConfig, "", "  ")
}

func main() {
	botToken := "8029568919:AAFlxxsYa0pQ5ZwioNx9be4L1BtForJ-vHY"
	if botToken == "" {
		log.Fatal("TELEGRAM_BOT_TOKEN environment variable is not set")
	}

	pref := tele.Settings{
		Token:  botToken,
		Poller: &tele.LongPoller{Timeout: 10 * time.Second},
	}

	bot, err := tele.NewBot(pref)
	if err != nil {
		log.Fatal(err)
	}

	bot.Handle(tele.OnText, func(c tele.Context) error {

		var (
			user = c.Sender()
			text = c.Text()
		)

		uri := text
		config, err := parseURI(uri)
		if err != nil {
			_, err := bot.Send(user, "Invalid URI. Please send a valid URI.")
			if err != nil {
				return err
			}
		}

		xrayJSON, err := generateXrayConfig(config)
		if err != nil {
			_, err := bot.Send(user, "Failed to generate Xray configuration.")
			if err != nil {
				return err
			}
		} else {
			_, err := bot.Send(user, fmt.Sprintf("Xray Configuration:\n```json\n%s\n```", xrayJSON), &tele.SendOptions{
				ParseMode: tele.ModeMarkdown,
			})
			if err != nil {
				return err
			}
		}

		singboxJSON, err := generateSingboxConfig(config)
		if err != nil {
			_, err := bot.Send(user, "Failed to generate Sing-box configuration.")
			if err != nil {
				return err
			}
		} else {
			_, err := bot.Send(user, fmt.Sprintf("Sing-box Configuration:\n```json\n%s\n```", singboxJSON), &tele.SendOptions{
				ParseMode: tele.ModeMarkdown,
			})
			if err != nil {
				return err
			}
		}

		return c.Send(text)
	})

	log.Println("Bot is running...")
	bot.Start()
}

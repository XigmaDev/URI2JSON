package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/joho/godotenv"
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
	Network       string
	PublicKey     string
	ShortID       string
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
type SingboxVmessConfig struct {
	//Dns       []string         `json:"dns"`
	Log       Log              `json:"log"`
	Inbounds  []InboundSingbox `json:"inbounds"`
	Outbounds []VmessSingBox   `json:"outbounds"`
}

type SingboxVlessConfig struct {
	//Dns       []string         `json:"dns"`
	Log       Log              `json:"log"`
	Inbounds  []InboundSingbox `json:"inbounds"`
	Outbounds []VlessSingBox   `json:"outbounds"`
}
type SingboxTrojanConfig struct {
	//Dns       []string         `json:"dns"`
	Log       Log              `json:"log"`
	Inbounds  []InboundSingbox `json:"inbounds"`
	Outbounds []TrojanSingBox  `json:"outbounds"`
}
type SingboxSSConfig struct {
	//Dns       []string             `json:"dns"`
	Log       Log                  `json:"log"`
	Inbounds  []InboundSingbox     `json:"inbounds"`
	Outbounds []ShadowsocksSingBox `json:"outbounds"`
}

// "log": {
//         "level": "error"
//     },

type Log struct {
	Level string `json:"level"`
}

// "inbounds": [
//         {
//             "domain_strategy": "",
//             "listen": "0.0.0.0",
//             "listen_port": 2080,
//             "sniff": true,
//             "sniff_override_destination": false,
//             "tag": "mixed-in",
//             "type": "mixed"
//         }
//     ],

type InboundSingbox struct {
	Type          string `json:"type"`
	Tag           string `json:"tag"`
	Listen        string `json:"listen"`
	Port          int    `json:"listen_port"`
	Sniff         bool   `json:"sniff"`
	SniffOverride bool   `json:"sniff_override_destination"`
	Domain        string `json:"domain_strategy"`
}

// type OutboundSingbox struct {
// 	Type       string            `json:"type"`
// 	Tag        string            `json:"tag"`
// 	Server     string            `json:"server"`
// 	ServerPort int               `json:"server_port"`
// 	UUID       string            `json:"uuid"`
// 	Network    string            `json:"network"`
// 	TLS        TLSSingBox        `json:"tls"`
// 	MULTIPLEX  MULTIPLEXSingBox  `json:"multiplex"`
// 	Transport  TransportSingBox  `json:"transport"`
// 	UdpOverTcp UdpOverTcpSingBox `json:"udp_over_tcp"`
// }

// https://sing-box.sagernet.org/configuration/outbound/trojan/
type TrojanSingBox struct {
	Type       string            `json:"type"`
	Tag        string            `json:"tag"`
	Server     string            `json:"server"`
	ServerPort int               `json:"server_port"`
	UUID       string            `json:"uuid"`
	Network    string            `json:"network"`
	TLS        TLSSingBox        `json:"tls"`
	MULTIPLEX  MULTIPLEXSingBox  `json:"multiplex"`
	Transport  TransportSingBox  `json:"transport"`
	UdpOverTcp UdpOverTcpSingBox `json:"udp_over_tcp"`
	Password   string            `json:"password"`
}

// https://sing-box.sagernet.org/configuration/outbound/vless/
type VlessSingBox struct {
	Type           string            `json:"type"`
	Tag            string            `json:"tag"`
	Server         string            `json:"server"`
	ServerPort     int               `json:"server_port"`
	UUID           string            `json:"uuid"`
	Network        string            `json:"network"`
	TLS            TLSSingBox        `json:"tls"`
	MULTIPLEX      MULTIPLEXSingBox  `json:"multiplex"`
	Transport      TransportSingBox  `json:"transport"`
	UdpOverTcp     UdpOverTcpSingBox `json:"udp_over_tcp"`
	Flow           string            `json:"flow"`
	PacketEncoding string            `json:"packet_encoding"`
}

// https://sing-box.sagernet.org/configuration/outbound/vmess/
type VmessSingBox struct {
	Type           string            `json:"type"`
	Tag            string            `json:"tag"`
	Server         string            `json:"server"`
	ServerPort     int               `json:"server_port"`
	UUID           string            `json:"uuid"`
	Network        string            `json:"network"`
	TLS            TLSSingBox        `json:"tls"`
	MULTIPLEX      MULTIPLEXSingBox  `json:"multiplex"`
	Transport      TransportSingBox  `json:"transport"`
	UdpOverTcp     UdpOverTcpSingBox `json:"udp_over_tcp"`
	Security       string            `json:"security"`
	AlterID        int               `json:"alter_id"`
	GlobalPadding  bool              `json:"global_padding"`
	AuthLength     bool              `json:"authenticated_length"`
	PacketEncoding string            `json:"packet_encoding"`
}

// https://sing-box.sagernet.org/configuration/outbound/shadowsocks/
type ShadowsocksSingBox struct {
	Type       string            `json:"type"`
	Tag        string            `json:"tag"`
	Server     string            `json:"server"`
	ServerPort int               `json:"server_port"`
	UUID       string            `json:"uuid"`
	Network    string            `json:"network"`
	TLS        TLSSingBox        `json:"tls"`
	MULTIPLEX  MULTIPLEXSingBox  `json:"multiplex"`
	Transport  TransportSingBox  `json:"transport"`
	UdpOverTcp UdpOverTcpSingBox `json:"udp_over_tcp"`
	Method     string            `json:"method"`
	Password   string            `json:"password"`
	Plugin     string            `json:"plugin"`
	PluginOpts string            `json:"plugin_opts"`
}

type UdpOverTcpSingBox struct {
	Enabled bool `json:"enabled"`
	Version int  `json:"version"`
}

type MULTIPLEXSingBox struct {
	Enabled       bool   `json:"enabled"`
	Protocol      string `json:"protocol"`
	Maxconnection int    `json:"max_connections"`
	MinStream     int    `json:"min_stream"`
	MaxStream     int    `json:"max_stream"`
	Padding       bool   `json:"padding"`
	Brutal        string `json:"brutal"`
}

//	"tls": {
//	                "alpn": [
//	                    "h2"
//	                ],
//	                "enabled": true,
//	                "server_name": "test.rs",
//	                "utls": {
//	                    "enabled": true,
//	                    "fingerprint": "chrome"
//	                }
//	            },
type TLSSingBox struct {
	Enabled    bool           `json:"enabled"`
	ServerName string         `json:"server_name"`
	ALPN       []string       `json:"alpn"`
	Insecure   bool           `json:"insecure"`
	MinVersion string         `json:"min_version"`
	MaxVersion string         `json:"max_version"`
	UTLS       UTLSSingBox    `json:"utls"`
	Reality    RealitySingBox `json:"reality"`
}

type UTLSSingBox struct {
	Enabled     bool   `json:"enabled"`
	Fingerprint string `json:"fingerprint"`
}

type RealitySingBox struct {
	Enabled   bool   `json:"enabled"`
	PublicKey string `json:"public_key"`
	ShortID   string `json:"short_id"`
}

type TransportSingBox struct {
	Type string `json:"type"`
	Host string `json:"host"`
	Path string `json:"path"`
}

func getString(data map[string]interface{}, key string) string {
	if value, ok := data[key]; ok {
		if str, ok := value.(string); ok {
			return str
		}
	}
	return ""
}

func parseURI(uri string) (*Config, error) {
	if strings.HasPrefix(uri, "vmess://") {
		decoded, err := base64.StdEncoding.DecodeString(uri[8:])
		if err != nil {
			return nil, fmt.Errorf("failed to decode Base64: %v", err)
		}
		var rawConfig map[string]interface{}
		err = json.Unmarshal(decoded, &rawConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal JSON: %v", err)
		}
		config := &Config{
			Protocol:    "vmess",
			UUID:        getString(rawConfig, "id"),
			Address:     getString(rawConfig, "add"),
			Port:        getString(rawConfig, "port"),
			Type:        getString(rawConfig, "type"),
			Path:        getString(rawConfig, "path"),
			Host:        getString(rawConfig, "host"),
			Security:    getString(rawConfig, "tls"),
			Network:     getString(rawConfig, "net"),
			Fingerprint: getString(rawConfig, "fingerprint"),
			ALPN:        getString(rawConfig, "alpn"),
		}

		return config, nil
	} else {
		parsedURL, err := url.Parse(uri)
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
		case "vless":
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

	port, err := strconv.Atoi(config.Port)
	if err != nil {
		return nil, fmt.Errorf("invalid port: %v", err)
	}

	switch config.Protocol {
	case "vmess":
		singboxVmessConfig := SingboxVmessConfig{
			Log: Log{
				Level: "error",
			},
			Inbounds: []InboundSingbox{
				{
					Type:          "mixed",
					Tag:           "mixed-in",
					Listen:        "::",
					Port:          2080,
					Sniff:         true,
					SniffOverride: false,
					Domain:        "",
				},
			},
		}
		outbound := VmessSingBox{
			Type:           config.Protocol,
			Tag:            fmt.Sprintf("%s-out", config.Protocol),
			Server:         config.Address,
			ServerPort:     port,
			UUID:           config.UUID,
			Security:       "auto",
			AlterID:        0,
			GlobalPadding:  false,
			AuthLength:     true,
			PacketEncoding: "",
			Network:        config.Network,
			TLS: TLSSingBox{
				Enabled:    true,
				ServerName: config.SNI,
				ALPN:       strings.Split(config.ALPN, ","),
				MinVersion: "",
				MaxVersion: "",
				Insecure:   config.AllowInsecure == "1",
				UTLS: UTLSSingBox{
					Enabled:     true,
					Fingerprint: config.Fingerprint,
				},
			},
			Transport: TransportSingBox{
				Type: config.Type,
				Host: config.Host,
				Path: config.Path,
			},
		}
		singboxVmessConfig.Outbounds = []VmessSingBox{outbound}
		return json.MarshalIndent(singboxVmessConfig, "", "  ")
	case "vless":
		singboxVlessConfig := SingboxVlessConfig{
			Log: Log{
				Level: "error",
			},
			Inbounds: []InboundSingbox{
				{
					Type:          "mixed",
					Tag:           "mixed-in",
					Listen:        "::",
					Port:          2080,
					Sniff:         true,
					SniffOverride: false,
					Domain:        "",
				},
			},
		}
		outbound := VlessSingBox{
			Type:   config.Protocol,
			Tag:    fmt.Sprintf("%s-out", config.Protocol),
			Server: config.Address,
			ServerPort: func() int {
				port, _ := strconv.Atoi(config.Port)
				return port
			}(),
			UUID:    config.UUID,
			Network: config.Type,
			TLS: TLSSingBox{
				Enabled:    true,
				ServerName: config.SNI,
				ALPN:       strings.Split(config.ALPN, ","),
				MinVersion: "",
				MaxVersion: "",
				Insecure:   config.AllowInsecure == "1",
				UTLS: UTLSSingBox{
					Enabled:     true,
					Fingerprint: config.Fingerprint,
				},
				Reality: RealitySingBox{
					Enabled:   false,
					PublicKey: config.PublicKey,
					ShortID:   config.ShortID,
				},
			},
			Transport: TransportSingBox{
				Type: config.Type,
				Host: config.Host,
				Path: config.Path,
			},
			MULTIPLEX: MULTIPLEXSingBox{
				Enabled:  false,
				Protocol: "",
			},
			Flow: config.Security,
		}
		singboxVlessConfig.Outbounds = []VlessSingBox{outbound}
		return json.MarshalIndent(singboxVlessConfig, "", "  ")
	case "ss":
		singboxssConfig := SingboxSSConfig{
			Log: Log{
				Level: "error",
			},
			Inbounds: []InboundSingbox{
				{
					Type:          "mixed",
					Tag:           "mixed-in",
					Listen:        "::",
					Port:          2080,
					Sniff:         true,
					SniffOverride: false,
					Domain:        "",
				},
			},
		}
		outbound := ShadowsocksSingBox{
			Type:   "shadowsocks",
			Tag:    fmt.Sprintf("%s-out", config.Protocol),
			Server: config.Address,
			ServerPort: func() int {
				port, _ := strconv.Atoi(config.Port)
				return port
			}(),
			Network:    config.Network,
			Method:     config.Method,
			Password:   config.Password,
			Plugin:     "",
			PluginOpts: "",
			UdpOverTcp: UdpOverTcpSingBox{
				Enabled: false,
				Version: 0,
			},
			MULTIPLEX: MULTIPLEXSingBox{
				Enabled:  false,
				Protocol: "",
			},
		}
		singboxssConfig.Outbounds = []ShadowsocksSingBox{outbound}
		return json.MarshalIndent(singboxssConfig, "", "  ")
	case "trojan":
		singboxTrojanConfig := SingboxTrojanConfig{
			Log: Log{
				Level: "error",
			},
			Inbounds: []InboundSingbox{
				{
					Type:          "mixed",
					Tag:           "mixed-in",
					Listen:        "::",
					Port:          2080,
					Sniff:         true,
					SniffOverride: false,
					Domain:        "",
				},
			},
		}
		outbound := TrojanSingBox{
			Type:   "trojan",
			Tag:    fmt.Sprintf("%s-out", config.Protocol),
			Server: config.Address,
			ServerPort: func() int {
				port, _ := strconv.Atoi(config.Port)
				return port
			}(),
			Password: config.Password,
			TLS: TLSSingBox{
				Enabled:    true,
				ServerName: config.SNI,
				ALPN:       strings.Split(config.ALPN, ","),
				MinVersion: "",
				MaxVersion: "",
				Insecure:   config.AllowInsecure == "1",
				UTLS: UTLSSingBox{
					Enabled:     true,
					Fingerprint: config.Fingerprint,
				},
				Reality: RealitySingBox{
					Enabled:   false,
					PublicKey: config.PublicKey,
					ShortID:   config.ShortID,
				},
			},
			MULTIPLEX: MULTIPLEXSingBox{
				Enabled:  false,
				Protocol: "",
			},
			Transport: TransportSingBox{
				Type: config.Type,
				Host: config.Host,
				Path: config.Path,
			},
		}
		singboxTrojanConfig.Outbounds = []TrojanSingBox{outbound}
		return json.MarshalIndent(singboxTrojanConfig, "", "  ")
	default:
		return nil, fmt.Errorf("unsupported protocol: %s", config.Protocol)
	}
}

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	botToken := os.Getenv("BOT_TOKEN")
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
			jsonFilePath := "config.json"
			if err := os.WriteFile(jsonFilePath, singboxJSON, 0644); err != nil {
				fmt.Println("Error writing JSON file:", err)
				return err
			} else {
				_, err := bot.Send(user, fmt.Sprintf("Sing-box Configuration:\n```json\n%s\n```", singboxJSON), &tele.SendOptions{
					ParseMode: tele.ModeMarkdown,
				})
				if err != nil {
					return err
				}
				document := &tele.Document{File: tele.FromDisk(jsonFilePath), FileName: "SingBoxConfig.json", MIME: "application/json", Caption: "Sing-box Configuration"}
				_, err = bot.Send(user, document)
				if err != nil {
					fmt.Println("Error sending document:", err)
					return err
				}
			}
			defer os.Remove(jsonFilePath)
		}

		return c.Send(text)
	})

	log.Println("Bot is running...")
	bot.Start()
}

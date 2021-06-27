package vless

import (
	"fmt"
	"math/rand"
	"net"
	"runtime"

	"github.com/gofrs/uuid"
)

const (
	XRO          = "xtls-rprx-origin"
	XRD          = "xtls-rprx-direct"
	XRS          = "xtls-rprx-splice"
	Version byte = 0 // protocol version. preview version is 0
)

// Request Options
const (
	OptionChunkStream  byte = 1
	OptionChunkMasking byte = 4
)

// Security type vless
type Security = byte

// Cipher types
const (
	SecurityAES128GCM        Security = 3
	SecurityCHACHA20POLY1305 Security = 4
	SecurityNone             Security = 5
)

// CipherMapping return
var CipherMapping = map[string]byte{
	"none":              SecurityNone,
	"aes-128-gcm":       SecurityAES128GCM,
	"chacha20-poly1305": SecurityCHACHA20POLY1305,
}

// Command types
const (
	CommandTCP byte = 1
	CommandUDP byte = 2
)

// Addr types
const (
	AtypIPv4       byte = 1
	AtypDomainName byte = 2
	AtypIPv6       byte = 3
)

// DstAddr store destination address
type DstAddr struct {
	UDP      bool
	AddrType byte
	Addr     []byte
	Port     uint
}

// Client is vless connection generator
type Client struct {
	UUID   *uuid.UUID
	Addons *Addons
	security Security
}

// Config of vless
type Config struct {
	UUID     string
	Security string
	Port     string
	HostName string
}

// StreamConn return a Conn with net.Conn and DstAddr
func (c *Client) StreamConn(conn net.Conn, dst *DstAddr) (net.Conn, error) {
	return newConn(conn, c, dst)
}

// NewClient return Client instance
func NewClient(uuidStr string, addons *Addons) (*Client, error) {
	uid, err := uuid.FromString(uuidStr)
	if err != nil {
		return nil, err
	}

	return &Client{
		UUID:   &uid,
		Addons: addons,
	}, nil
}

// NewClient return Client instance
func NewClient(config Config) (*Client, error) {
	uid, err := uuid.FromString(config.UUID)
	if err != nil {
		return nil, err
	}

	var security Security
	switch config.Security {
	case "aes-128-gcm":
		security = SecurityAES128GCM
	case "chacha20-poly1305":
		security = SecurityCHACHA20POLY1305
	case "none":
		security = SecurityNone
	case "auto":
		security = SecurityCHACHA20POLY1305
		if runtime.GOARCH == "amd64" || runtime.GOARCH == "s390x" || runtime.GOARCH == "arm64" {
			security = SecurityAES128GCM
		}
	default:
		return nil, fmt.Errorf("unknown security type: %s", config.Security)
	}

	return &Client{
		UUID:     &uid,
		security: security
	}, nil
}

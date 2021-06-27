package vless

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"hash/fnv"
	"io"
	"io/ioutil"
	"math/rand"
	"net"
	"time"

	"github.com/Dreamacro/clash/transport/vmess"
	"github.com/gofrs/uuid"
	xtls "github.com/xtls/go"
	"google.golang.org/protobuf/proto"
	"golang.org/x/crypto/chacha20poly1305"
)

func init() {
	rand.Seed(time.Now().UnixNano())
}

type Conn struct {
	net.Conn
	dst      *vmess.DstAddr
	id       *uuid.UUID
	addons   *Addons
	security    byte
	received bool
}

func (vc *Conn) Read(b []byte) (int, error) {
	if vc.received {
		return vc.Conn.Read(b)
	}

	if err := vc.recvResponse(); err != nil {
		return 0, err
	}
	vc.received = true
	return vc.Conn.Read(b)
}

func (vc *Conn) sendRequest() error {
	timestamp := time.Now()

	h := hmac.New(md5.New, vc.id.Bytes())
	binary.Write(h, binary.BigEndian, uint64(timestamp.Unix()))
	mbuf := &bytes.Buffer{}
	mbuf.Write(h.Sum(nil))

	buf := &bytes.Buffer{}

	buf.WriteByte(Version)   // protocol version
	buf.Write(vc.id.Bytes()) // 16 bytes of uuid
	if vc.addons != nil {
		bytes, err := proto.Marshal(vc.addons)
		if err != nil {
			return err
		}

		buf.WriteByte(byte(len(bytes)))
		buf.Write(bytes)
	} else {
		buf.WriteByte(0) // addon data length. 0 means no addon data
	}

	// command
	if vc.dst.UDP {
		buf.WriteByte(vmess.CommandUDP)
	} else {
		buf.WriteByte(vmess.CommandTCP)
	}

	// Port AddrType Addr
	binary.Write(buf, binary.BigEndian, uint16(vc.dst.Port))
	buf.WriteByte(vc.dst.AddrType)
	buf.Write(vc.dst.Addr)

	//mbuf.Write(buf.Bytes())
	//_, err := vc.Conn.Write(mbuf.Bytes())
	_, err := vc.Conn.Write(buf.Bytes())
	return err
}

func (vc *Conn) recvResponse() error {
	var err error
	buf := make([]byte, 1)
	_, err = io.ReadFull(vc.Conn, buf)
	if err != nil {
		return err
	}

	if buf[0] != Version {
		return errors.New("unexpected response version")
	}

	_, err = io.ReadFull(vc.Conn, buf)
	if err != nil {
		return err
	}

	length := int64(buf[0])
	if length != 0 { // addon data length > 0
		io.CopyN(ioutil.Discard, vc.Conn, length) // just discard
	}

	return nil
}

// newConn return a Conn instance
func newConn(conn net.Conn, client *Client, dst *vmess.DstAddr) (*Conn, error) {
	c := &Conn{
		id:   client.UUID,
		Conn: conn,
		dst:  dst,
	}
	if !dst.UDP && client.Addons != nil {
		switch client.Addons.Flow {
		case XRO, XRD, XRS:
			if xtlsConn, ok := conn.(*xtls.Conn); ok {
				c.addons = client.Addons
				xtlsConn.RPRX = true
				xtlsConn.MARK = "XTLS"
				if client.Addons.Flow == XRS {
					client.Addons.Flow = XRD //force to XRD
				}
				if client.Addons.Flow == XRD {
					xtlsConn.DirectMode = true
				}
			}
		}
	}
	if err := c.sendRequest(); err != nil {
		return nil, err
	}
	return c, nil
}

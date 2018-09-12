package main

import (
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"log"
	"math/big"
	"net"
	"strconv"
	"time"

	quic "github.com/lucas-clemente/quic-go"
	"github.com/songgao/packets/ethernet"
	"github.com/songgao/water"
	aead "golang.org/x/crypto/chacha20poly1305"
)

var debug bool
var key string
var routing map[string]quic.Stream
var mapconn map[string]quic.Session
var localmac string
var forwardOnly bool
var ifce *water.Interface

func main() {
	key = "Password"
	forwardOnly = false
	routing = make(map[string]quic.Stream)
	mapconn = make(map[string]quic.Session)
	debug = true

	interfaces, err := net.Interfaces()
	for _, inter := range interfaces {
		ifname := inter.Name
		mac := inter.HardwareAddr
		//This is the name of the TAP device
		if ifname == "本地连接 7" {
			localmac = hex.EncodeToString(mac)
		}
		if debug {
			log.Println(ifname)
			log.Println(mac)
		}
	}

	if !forwardOnly {
		ifce, err = water.New(water.Config{
			DeviceType: water.TAP,
		})
		if err != nil {
			log.Fatal(err)
		}
		go ServerTX()
	}

	listener, err := quic.ListenAddr("127.0.0.1:6060", generateTLSConfig(), nil)
	if err != nil {
		log.Fatalln(err)
	}
	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Fatalln(err)
		}
		go ServerRX(conn)
	}

}

func ServerTX() {
	ciper, err := gerateAEAD(key)
	if err != nil {
		log.Panicln(err)
		return
	}
	var frame ethernet.Frame
	for {
		frame.Resize(1500)
		n, err := ifce.Read([]byte(frame))
		if err != nil {
			log.Fatal(err)
		}
		frame = frame[:n]
		ciphertext := ciper.Seal(nil, geratenonce(), []byte(frame), nil)
		srcstr := hex.EncodeToString(frame.Source())
		dststr := hex.EncodeToString(frame.Destination())
		if debug {
			log.Printf("Dst: %s\n", frame.Destination())
			log.Printf("Src: %s\n", frame.Source())
			log.Printf("Ethertype: % x\n", frame.Ethertype())
			log.Printf("Payload: % x\n", frame.Payload())
		}
		if dststr == "ffffffffffff" {
			//broadcast
			for todst, tostream := range routing {
				//avoid loopback
				if todst == localmac {
					continue
				}
				if todst == srcstr {
					continue
				}
				if debug {
					log.Printf("↑↑↑↑↑TX-Broadcast↑↑↑↑↑")
				}
				conn, ok := mapconn[todst]
				if !ok {
					continue
				} else {
					_, err = tostream.Write(ciphertext)
					if err != nil {
						conn.Close()
						delete(routing, todst)
						delete(mapconn, todst)
						log.Println(err)
						continue
					}
				}
			}
		} else {
			//unicast
			tostream, ok := routing[dststr]
			if !ok {
				//according to the rule:broadcast this frame or handle it to system
				for todst, tostream := range routing {
					//avoid loopback
					if todst == localmac {
						continue
					}
					if todst == srcstr {
						continue
					}
					if debug {
						log.Printf("↑↑↑↑↑TX-Broadcast-Study↑↑↑↑↑")
					}
					conn, ok := mapconn[todst]
					if !ok {
						continue
					} else {
						_, err = tostream.Write(ciphertext)
						if err != nil {
							conn.Close()
							delete(routing, todst)
							delete(mapconn, todst)
							log.Println(err)
							continue
						}
					}
				}
			} else {
				// if dst online send it directly
				if debug {
					log.Printf("↑↑↑↑↑TX-Unicast↑↑↑↑↑")
				}
				conn, ok := mapconn[dststr]
				if !ok {
					continue
				} else {
					_, err = tostream.Write(ciphertext)
					if err != nil {
						conn.Close()
						delete(routing, dststr)
						delete(mapconn, dststr)
						log.Println(err)
						continue
					}
				}
			}
		}
	}
}

// Start a server that echos all data on the first stream opened by the client
func ServerRX(thisconn quic.Session) {
	ciper, err := gerateAEAD(key)
	if err != nil {
		thisconn.Close()
		log.Println(err)
		return
	}
	thisconnmac := []string{}
	stream, err := thisconn.AcceptStream()
	if err != nil {
		for item := range thisconnmac {
			delete(routing, thisconnmac[item])
			delete(mapconn, thisconnmac[item])
		}
		thisconn.Close()
		log.Println(err)
		return
	}
	var frame ethernet.Frame
	for {
		message := make([]byte, 1048576)
		messagelen, err := stream.Read(message)
		if err != nil {
			stream.Close()
			thisconn.Close()
			log.Println(err)
			return
		}
		if messagelen == 0 {
			continue
		}
		plaintext, err := ciper.Open(nil, geratenonce(), message[:messagelen], nil)
		if err != nil {
			log.Println("Failed to decrypt or authenticate message:", err)
			continue
		}
		frame = ethernet.Frame([]byte(plaintext))
		srcstr := hex.EncodeToString(frame.Source())
		routing[srcstr] = stream
		mapconn[srcstr] = thisconn
		thisconnmac = append(thisconnmac, srcstr)
		dststr := hex.EncodeToString(frame.Destination())
		ciphertext := ciper.Seal(nil, geratenonce(), []byte(frame), nil)
		if debug {
			log.Printf("Dst: %s\n", frame.Destination())
			log.Printf("Src: %s\n", frame.Source())
			log.Printf("Ethertype: % x\n", frame.Ethertype())
			log.Printf("Payload: % x\n", frame.Payload())
		}
		if dststr == "ffffffffffff" {
			//broadcast
			for todst, tostream := range routing {
				//avoid loopback
				if tostream == stream {
					continue
				}
				if todst == srcstr {
					continue
				}
				if debug {
					log.Printf("↑↑↑↑↑Forward-Broadcast↑↑↑↑↑")
				}
				conn, ok := mapconn[todst]
				if !ok {
					continue
				} else {
					_, err = tostream.Write(ciphertext)
					if err != nil {
						delete(routing, todst)
						delete(mapconn, todst)
						conn.Close()
						log.Println(err)
						return
					}
				}
			}
			//write to local?
			if !forwardOnly {
				_, err = ifce.Write(frame)
				if err != nil {
					log.Fatal(err)
				}
				if debug {
					log.Printf("↑↑↑↑↑RX-Broadcast↑↑↑↑↑")
				}
			} else {
				if debug {
					log.Printf("↑↑↑↑↑Ignore-RX-Broadcast↑↑↑↑↑")
				}
			}
		} else {
			if dststr == localmac {
				if !forwardOnly {
					_, err = ifce.Write(frame)
					if err != nil {
						log.Fatal(err)
					}
					if debug {
						log.Printf("↑↑↑↑↑RX-Local↑↑↑↑↑")
					}
				}
			} else {
				tostream, ok := routing[dststr]
				if !ok {
					//according to the rule:broadcast this frame or handle it to system
					for todst, tostream := range routing {
						//avoid loopback
						if tostream == stream {
							continue
						}
						if todst == srcstr {
							continue
						}
						if debug {
							log.Printf("↑↑↑↑↑Forward-Broadcast-Study↑↑↑↑↑")
						}
						conn, ok := mapconn[todst]
						if !ok {
							continue
						} else {
							_, err = tostream.Write(ciphertext)
							if err != nil {
								delete(routing, todst)
								delete(mapconn, todst)
								conn.Close()
								log.Println(err)
								return
							}
						}
					}
				} else {
					// if dst online send it directly
					if debug {
						log.Printf("↑↑↑↑↑Forward↑↑↑↑↑")
					}
					conn, ok := mapconn[dststr]
					if !ok {
						continue
					} else {
						_, err = tostream.Write(ciphertext)
						if err != nil {
							delete(routing, dststr)
							delete(mapconn, dststr)
							conn.Close()
							log.Println(err)
							return
						}
					}
				}
			}
		}
	}
}

// Setup a bare-bones TLS config for the server
func generateTLSConfig() *tls.Config {
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		panic(err)
	}
	template := x509.Certificate{SerialNumber: big.NewInt(1)}
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		panic(err)
	}
	return &tls.Config{Certificates: []tls.Certificate{tlsCert}}
}

func geratenonce() []byte {
	hash := sha256.New()
	hash.Write([]byte(strconv.Itoa(int(time.Now().Unix()/300) * 300)))
	return hash.Sum(nil)[:12]
}

func gerateAEAD(password string) (AEAD cipher.AEAD, err error) {
	hash := sha256.New()
	hash.Write([]byte(password))
	return aead.New(hash.Sum(nil))
}

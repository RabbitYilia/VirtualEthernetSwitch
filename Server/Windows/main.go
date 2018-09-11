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
	"strconv"

	"time"

	quic "github.com/lucas-clemente/quic-go"
	"github.com/songgao/packets/ethernet"
	//"github.com/songgao/water"
	aead "golang.org/x/crypto/chacha20poly1305"
)

var debug bool
var key string
var routing map[string]quic.Stream

func main() {
	key = "Password"
	routing = make(map[string]quic.Stream)
	debug = true
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

// Start a server that echos all data on the first stream opened by the client
func ServerRX(conn quic.Session) {
	ciper, err := gerateAEAD(key)
	if err != nil {
		conn.Close()
		log.Println(err)
		return
	}
	stream, err := conn.AcceptStream()
	if err != nil {
		conn.Close()
		log.Println(err)
		return
	}
	var frame ethernet.Frame
	for {
		message := make([]byte, 1048576)
		messagelen, err := stream.Read(message)
		if err != nil {
			stream.Close()
			conn.Close()
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
		routing[hex.EncodeToString(frame.Source())] = stream
		if debug {
			log.Printf("-----RX-----")
			log.Printf("Dst: %s\n", frame.Destination())
			log.Printf("Src: %s\n", frame.Source())
			log.Printf("Ethertype: % x\n", frame.Ethertype())
			log.Printf("Payload: % x\n", frame.Payload())
		}
		//ciphertext := ciper.Seal(nil, geratenonce(), []byte("Get"), nil)
		//stream.Write(ciphertext)
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

package main

import (
	"crypto/cipher"
	"crypto/sha256"
	"crypto/tls"
	"log"
	"strconv"
	"time"

	quic "github.com/lucas-clemente/quic-go"
	"github.com/songgao/packets/ethernet"
	"github.com/songgao/water"
	aead "golang.org/x/crypto/chacha20poly1305"
)

var debug bool
var key string

func main() {
	key = "Password"
	//Init Interface
	debug = true
	config := water.Config{
		DeviceType: water.TAP,
	}
	config.Name = "O_O"

	ifce, err := water.New(config)
	if err != nil {
		log.Fatal(err)
	}

	//Init Connection
	session, err := quic.DialAddr("localhost:6060", &tls.Config{InsecureSkipVerify: true}, nil)
	if err != nil {
		panic(err)
	}
	stream, err := session.OpenStreamSync()
	if err != nil {
		panic(err)
	}
	go readframe(ifce, stream)
	writeframe(ifce, stream)

	ifce.Close()
	session.Close()
}

func readframe(ifce *water.Interface, stream quic.Stream) {
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
		if debug {
			log.Printf("-----TX-----")
			log.Printf("Dst: %s\n", frame.Destination())
			log.Printf("Src: %s\n", frame.Source())
			log.Printf("Ethertype: % x\n", frame.Ethertype())
			log.Printf("Payload: % x\n", frame.Payload())
		}
		ciphertext := ciper.Seal(nil, geratenonce(), []byte(frame), nil)
		_, err = stream.Write(ciphertext)
		if err != nil {
			log.Panicln(err)
			return
		}
	}
}

func writeframe(ifce *water.Interface, stream quic.Stream) {
	recvbuffer := make([]byte, 1048576)
	ciper, err := gerateAEAD(key)
	if err != nil {
		log.Panicln(err)
		return
	}
	var frame ethernet.Frame
	for {
		recvmsglen, err := stream.Read(recvbuffer)
		plaintext, err := ciper.Open(nil, geratenonce(), recvbuffer[:recvmsglen], nil)
		frame = ethernet.Frame([]byte(plaintext))
		_, err = ifce.Write(frame)
		if err != nil {
			log.Fatal(err)
		}
		if debug {
			log.Printf("-----RX-----")
			log.Printf("Dst: %s\n", frame.Destination())
			log.Printf("Src: %s\n", frame.Source())
			log.Printf("Ethertype: % x\n", frame.Ethertype())
			log.Printf("Payload: % x\n", frame.Payload())
		}
	}
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

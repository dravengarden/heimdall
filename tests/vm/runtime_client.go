package main

import (
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"
)

func main() {
	if len(os.Args) != 2 {
		panic("usage: runtime-client tcp|udp4|udp6")
	}
	mode := os.Args[1]
	if mode == "tcp" {
		tcp()
	} else {
		udp(mode)
	}
	fmt.Printf("go-netgo-%s-ok\n", mode)
}

func tcp() {
	conn, err := net.DialTimeout("tcp", "fixture.test:18080", 5*time.Second)
	if err != nil {
		panic(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.WriteString(conn, "GET / HTTP/1.0\r\nHost: fixture.test\r\n\r\n"); err != nil {
		panic(err)
	}
	body, err := io.ReadAll(conn)
	if err != nil || !strings.HasSuffix(string(body), "fixture-v4") {
		panic(fmt.Sprintf("unexpected TCP response: %q (%v)", body, err))
	}
}

func udp(mode string) {
	network, target, expected := "udp4", "127.0.0.1:18082", "udp-v4:runtime-go"
	if mode == "udp6" {
		network, target, expected = "udp6", "[::1]:18083", "udp-v6:runtime-go"
	} else if mode != "udp4" {
		panic("unknown mode: " + mode)
	}
	peer, err := net.ResolveUDPAddr(network, target)
	if err != nil {
		panic(err)
	}
	conn, err := net.DialUDP(network, nil, peer)
	if err != nil {
		panic(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write([]byte("runtime-go")); err != nil {
		panic(err)
	}
	response := make([]byte, 128)
	n, source, err := conn.ReadFromUDP(response)
	if err != nil || string(response[:n]) != expected || source.String() != peer.String() {
		panic(fmt.Sprintf("unexpected UDP response: %q from %v (%v)", response[:n], source, err))
	}
}

// Command tcpcut is a TCP relay that can be told to drop its connections.
// The integration tests mount the share through it and cut the connections
// under the client, which is what a tunnel that reconnects looks like from
// both ends: the mount has to resume on its own.
//
// Any connection to the control address cuts every relayed connection; the
// relay keeps listening, so the client can come back at once.
package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
)

func main() {
	listen := flag.String("listen", "127.0.0.1:1446", "address clients connect to")
	to := flag.String("to", "127.0.0.1:1445", "address of the server")
	control := flag.String("control", "127.0.0.1:1447", "address that cuts the connections when connected to")
	flag.Parse()

	var (
		mu    sync.Mutex
		conns = map[net.Conn]struct{}{}
	)
	track := func(c net.Conn, add bool) {
		mu.Lock()
		defer mu.Unlock()
		if add {
			conns[c] = struct{}{}
		} else {
			delete(conns, c)
		}
	}

	cl, err := net.Listen("tcp", *control)
	if err != nil {
		log.Fatal(err)
	}
	go func() {
		for {
			c, err := cl.Accept()
			if err != nil {
				log.Fatal(err)
			}
			mu.Lock()
			n := len(conns) / 2
			for rc := range conns {
				rc.Close()
			}
			mu.Unlock()
			fmt.Fprintf(c, "cut %d\n", n)
			c.Close()
		}
	}()

	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		log.Fatal(err)
	}
	for {
		in, err := ln.Accept()
		if err != nil {
			log.Fatal(err)
		}
		go func() {
			out, err := net.Dial("tcp", *to)
			if err != nil {
				in.Close()
				return
			}
			track(in, true)
			track(out, true)
			done := make(chan struct{}, 2)
			pipe := func(dst, src net.Conn) {
				io.Copy(dst, src)
				// Closing both ends makes the other direction stop too.
				dst.Close()
				src.Close()
				done <- struct{}{}
			}
			go pipe(out, in)
			go pipe(in, out)
			<-done
			<-done
			track(in, false)
			track(out, false)
		}()
	}
}

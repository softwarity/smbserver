// Command smbserver serves a directory over SMB. It is the manual test
// bench of the smbserver package and what its integration tests run.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/softwarity/smbserver"
)

func main() {
	var (
		root     = flag.String("root", ".", "directory to serve")
		addr     = flag.String("addr", ":1445", "address to listen on")
		share    = flag.String("share", "share", "share name")
		user     = flag.String("user", "user", "user name")
		password = flag.String("password", os.Getenv("SMB_PASSWORD"), "password (default $SMB_PASSWORD)")
		allow    = flag.String("allow", "", "comma separated source prefixes to accept (default any)")
		readOnly = flag.Bool("readonly", false, "refuse modifications")
		verbose  = flag.Bool("v", false, "log connections and sessions")
	)
	flag.Parse()
	if *password == "" {
		fmt.Fprintln(os.Stderr, "smbserver: a password is required (-password or $SMB_PASSWORD)")
		os.Exit(2)
	}
	cfg := smbserver.Config{
		Root:     *root,
		Share:    *share,
		User:     *user,
		NTHash:   smbserver.NTHash(*password),
		ReadOnly: *readOnly,
	}
	if *verbose {
		cfg.Logf = log.Printf
	}
	for _, p := range strings.Split(*allow, ",") {
		if p = strings.TrimSpace(p); p == "" {
			continue
		}
		prefix, err := netip.ParsePrefix(p)
		if err != nil {
			// A bare address is the prefix that holds only itself.
			a, aerr := netip.ParseAddr(p)
			if aerr != nil {
				log.Fatalf("smbserver: -allow: %v", err)
			}
			prefix = netip.PrefixFrom(a, a.BitLen())
		}
		cfg.Allow = append(cfg.Allow, prefix)
	}

	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Fatalf("smbserver: %v", err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	log.Printf("serving %s as //%s/%s", *root, ln.Addr(), *share)
	if err := smbserver.Serve(ctx, ln, cfg); err != nil {
		log.Fatal(err)
	}
}

package main

import (
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"os"

	"github.com/bajankristof/trustedproxy"
)

func main() {
	// tp := trustedproxy.Default() to use the default trusted proxy IP ranges (loopback and private networks)
	tp, err := trustedproxy.New(
		trustedproxy.WithString("127.0.0.1"),                                    // Add a concrete IP address as a trusted proxy
		trustedproxy.WithString("192.168.0.0/16"),                               // Add an IP address range as a trusted proxy
		trustedproxy.WithStrings("2001:db9::1", "2001:db9::2", "2001:db8::/32"), // Add multiple concrete IPv6 addresses as trusted proxies
		trustedproxy.WithPrefix(netip.MustParsePrefix("2001:db8::/32")),         // Add an IP address range as a trusted proxy using net.IPNet
	)

	if err != nil {
		slog.Error(err.Error())
		os.Exit(1)
	}

	http.Handle("/", tp.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Println(r.RemoteAddr)               // Prints the real client IP address
		fmt.Println(trustedproxy.RemoteAddr(r)) // Prints the remote address of the reverse proxy
		fmt.Println(trustedproxy.IsSecure(r))   // Prints whether the request can be considered secure
		if _, err := w.Write([]byte("Hello, World!")); err != nil {
			slog.Error(err.Error())
		}
	})))

	if err := http.ListenAndServe(":8080", nil); err != nil {
		slog.Error(err.Error())
		os.Exit(1)
	}
}

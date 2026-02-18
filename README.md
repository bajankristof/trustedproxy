# Trusted proxy net/http middleware

[bajankristof/trustedproxy](https://github.com/bajankristof/trustedproxy) is a net/http middleware for Go that helps you get the real client IP address (using the rightmost non-trusted IP algorithm) and scheme when your application is behind a trusted proxy. It uses a list of trusted proxy IP address prefixes to determine if the request is coming from a trusted proxy and then updates the request's RemoteAddr based on the X-Forwarded-For header and marks the request as secure if the X-Forwarded-Proto header indicates that the original request was made over HTTPS.

You can use `trustedproxy.IsSecure(r)` to check whether the request can be considered secure.
> The request can only be considered secure if it came from a trusted proxy with the X-Forwarded-Proto header set to "https" or if the request did NOT come from a trusted proxy but was made over HTTPS.

You can also use `trustedproxy.RemoteAddr(r)` to get the remote address of the reverse proxy that forwarded the request.
> If the request did NOT come from a trusted proxy, this function will return the same value as `r.RemoteAddr`.

The middleware follows the standard net/http middleware pattern and can be easily integrated into your existing Go web application.

## Installation

```bash
go get github.com/bajankristof/trustedproxy
```

## Usage

```go
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
```

package trustedproxy

import (
	"context"
	"net/http"
)

type contextKey struct{}

var (
	infoKey = contextKey{}
)

type info struct {
	secure     bool
	remoteAddr string
}

// IsSecure reports whether the request can be considered secure.
// A request is considered secure if it came from a trusted proxy with
// the X-Forwarded-Proto header set to "https", or if it did not come
// from a trusted proxy but was made over HTTPS (r.TLS != nil).
// When the request came from a trusted proxy, r.TLS is ignored —
// only X-Forwarded-Proto determines the result.
func IsSecure(r *http.Request) bool {
	if pi, ok := r.Context().Value(infoKey).(*info); ok {
		return pi.secure
	}

	return r.TLS != nil
}

// RemoteAddr returns the remote address of the reverse proxy that forwarded the request.
// If the request did not come from a trusted proxy, it returns the same value as r.RemoteAddr.
func RemoteAddr(r *http.Request) string {
	if pi, ok := r.Context().Value(infoKey).(*info); ok {
		return pi.remoteAddr
	}

	return r.RemoteAddr
}

// Scheme returns the scheme of the request, either "http" or "https".
// It returns "https" if the request is considered secure, and "http" otherwise.
func Scheme(r *http.Request) string {
	if IsSecure(r) {
		return "https"
	}

	return "http"
}

// withInfo returns a copy of the request
// with the given info added to its context
// and its RemoteAddr field set to the remote address of the proxy.
func withInfo(r *http.Request, pi *info) *http.Request {
	r = r.WithContext(context.WithValue(r.Context(), infoKey, pi))
	r.RemoteAddr = pi.remoteAddr
	return r
}

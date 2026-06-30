package trustedproxy

import (
	"crypto/tls"
	"net/http"
	"testing"
)

func TestIsSecure(t *testing.T) {
	tests := map[string]struct {
		tls  *tls.ConnectionState
		pi   *info
		want bool
	}{
		"no info, no TLS":    {},
		"no info, TLS":       {tls: &tls.ConnectionState{}, want: true},
		"info: secure=true":  {pi: &info{secure: true}, want: true},
		"info: secure=false": {pi: &info{secure: false}},
		"info: secure=false, TLS": {tls: &tls.ConnectionState{}, pi: &info{secure: false}},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			r, _ := http.NewRequest(http.MethodGet, "/", nil)
			r.TLS = test.tls
			if test.pi != nil {
				r = withInfo(r, test.pi)
			}
			if got := IsSecure(r); got != test.want {
				t.Errorf("got %v, want %v", got, test.want)
			}
		})
	}
}

func TestRemoteAddr(t *testing.T) {
	tests := map[string]struct {
		remoteAddr string
		pi         *info
		want       string
	}{
		"no info": {remoteAddr: "1.2.3.4:56789", want: "1.2.3.4:56789"},
		"with info": {
			remoteAddr: "192.168.1.1:12345",
			pi:         &info{remoteAddr: "1.2.3.4:0"},
			want:       "1.2.3.4:0",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			r, _ := http.NewRequest(http.MethodGet, "/", nil)
			r.RemoteAddr = test.remoteAddr
			if test.pi != nil {
				r = withInfo(r, test.pi)
			}
			if got := RemoteAddr(r); got != test.want {
				t.Errorf("got %q, want %q", got, test.want)
			}
		})
	}
}

func TestScheme(t *testing.T) {
	tests := map[string]struct {
		tls  *tls.ConnectionState
		pi   *info
		want string
	}{
		"no info, no TLS":    {want: "http"},
		"no info, TLS":       {tls: &tls.ConnectionState{}, want: "https"},
		"info: secure=true":  {pi: &info{secure: true}, want: "https"},
		"info: secure=false": {pi: &info{secure: false}, want: "http"},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			r, _ := http.NewRequest(http.MethodGet, "/", nil)
			r.TLS = test.tls
			if test.pi != nil {
				r = withInfo(r, test.pi)
			}
			if got := Scheme(r); got != test.want {
				t.Errorf("got %q, want %q", got, test.want)
			}
		})
	}
}

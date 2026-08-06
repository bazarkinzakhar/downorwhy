package network_test

import (
	"context"
	"net"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/downorwhy/downorwhy/internal/core/network"
	dowurl "github.com/downorwhy/downorwhy/internal/core/url"
	"github.com/downorwhy/downorwhy/internal/core/types"
)

type fixedIPResolver struct {
	addresses []netip.Addr
	err       error
}

func (r fixedIPResolver) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	if r.err != nil {
		return nil, r.err
	}
	return r.addresses, nil
}

func newTestClient(timeout time.Duration, maxRedirects int, maxBodyBytes int64) *network.Client {
	cfg := types.DefaultConfig()
	cfg.Timeout = timeout
	cfg.MaxRedirects = maxRedirects
	cfg.MaxBodyBytes = maxBodyBytes
	cfg.UserAgent = "DownOrWhy/test"

	return network.NewClient(network.ClientOptions{
		Config: cfg,
		Policy: dowurl.Policy{
			AllowPrivate: true,
		},
		Resolver: fixedIPResolver{
			addresses: []netip.Addr{
				netip.MustParseAddr("127.0.0.1"),
			},
		},
	})
}

func targetForServer(t *testing.T, server *httptest.Server, path string) dowurl.Target {
	t.Helper()

	port := strconv.Itoa(server.Listener.Addr().(*net.TCPAddr).Port)
	target, err := dowurl.Normalize("http://scanner.test:" + port + path)
	require.NoError(t, err)

	return target
}

func TestHTTPClientFetchSuccess(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "DownOrWhy/test", r.UserAgent())
		require.Equal(t, "/health", r.URL.Path)

		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Cache-Control", "public, max-age=60")
		w.WriteHeader(http.StatusOK)

		_, err := w.Write([]byte("healthy"))
		require.NoError(t, err)
	}))
	t.Cleanup(server.Close)

	client := newTestClient(2*time.Second, 10, 10<<20)
	response, err := client.Fetch(context.Background(), targetForServer(t, server, "/health"))

	require.NoError(t, err)
	require.NotNil(t, response)
	require.Equal(t, http.StatusOK, response.StatusCode)
	require.Equal(t, "HTTP/1.1", response.Proto)
	require.Equal(t, "text/plain; charset=utf-8", response.Header.Get("Content-Type"))
	require.Equal(t, []byte("healthy"), response.Body)
	require.False(t, response.BodyTruncated)
	require.NotNil(t, response.FinalURL)
	require.Equal(t, "/health", response.FinalURL.Path)
	require.Empty(t, response.Hops)
	require.GreaterOrEqual(t, response.Timings.TotalMS, int64(0))
	require.True(t, response.RemoteAddr.IsValid())
}

func TestHTTPClientFetchCapturesRedirectChain(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/first":
			http.Redirect(w, r, "/second", http.StatusFound)
		case "/second":
			http.Redirect(w, r, "/final", http.StatusMovedPermanently)
		case "/final":
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)

	client := newTestClient(2*time.Second, 10, 10<<20)
	response, err := client.Fetch(context.Background(), targetForServer(t, server, "/first"))

	require.NoError(t, err)
	require.Equal(t, http.StatusNoContent, response.StatusCode)
	require.NotNil(t, response.FinalURL)
	require.Equal(t, "/final", response.FinalURL.Path)
	require.Len(t, response.Hops, 2)

	require.Equal(t, http.StatusFound, response.Hops[0].StatusCode)
	require.Equal(t, "/second", response.Hops[0].Location)

	require.Equal(t, http.StatusMovedPermanently, response.Hops[1].StatusCode)
	require.Equal(t, "/final", response.Hops[1].Location)
}

func TestHTTPClientFetchStopsAtRedirectLimit(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/one":
			http.Redirect(w, r, "/two", http.StatusFound)
		case "/two":
			http.Redirect(w, r, "/three", http.StatusFound)
		case "/three":
			http.Redirect(w, r, "/four", http.StatusFound)
		default:
			w.WriteHeader(http.StatusNoContent)
		}
	}))
	t.Cleanup(server.Close)

	client := newTestClient(2*time.Second, 1, 10<<20)
	_, err := client.Fetch(context.Background(), targetForServer(t, server, "/one"))

	require.ErrorIs(t, err, types.ErrTooManyRedirects)
}

func TestHTTPClientFetchCapsBodyAtConfiguredLimit(t *testing.T) {
	const limit = 1024
	body := strings.Repeat("x", limit+100)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)

		_, err := w.Write([]byte(body))
		require.NoError(t, err)
	}))
	t.Cleanup(server.Close)

	client := newTestClient(2*time.Second, 10, limit)
	response, err := client.Fetch(context.Background(), targetForServer(t, server, "/"))

	require.NoError(t, err)
	require.True(t, response.BodyTruncated)
	require.Len(t, response.Body, limit)
}

func TestHTTPClientFetchReturnsTimeoutError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
			return
		case <-time.After(500 * time.Millisecond):
			w.WriteHeader(http.StatusOK)
		}
	}))
	t.Cleanup(server.Close)

	client := newTestClient(50*time.Millisecond, 10, 10<<20)
	_, err := client.Fetch(context.Background(), targetForServer(t, server, "/"))

	require.Error(t, err)
	require.True(t, errors.Is(err, types.ErrTimeout))
}

func TestHTTPClientFetchRejectsUnsafeInitialTarget(t *testing.T) {
	cfg := types.DefaultConfig()
	cfg.Timeout = time.Second

	client := network.NewClient(network.ClientOptions{
		Config: cfg,
		Policy: dowurl.DefaultPolicy(),
		Resolver: fixedIPResolver{
			addresses: []netip.Addr{
				netip.MustParseAddr("127.0.0.1"),
			},
		},
	})

	target, err := dowurl.Normalize("http://127.0.0.1:8080/")
	require.NoError(t, err)

	_, err = client.Fetch(context.Background(), target)

	require.ErrorIs(t, err, types.ErrUnsafeTarget)
}

func TestHTTPClientFetchReturnsUnreachableForResolverFailure(t *testing.T) {
	cfg := types.DefaultConfig()
	cfg.Timeout = time.Second

	client := network.NewClient(network.ClientOptions{
		Config: cfg,
		Policy: dowurl.Policy{
			AllowPrivate: true,
		},
		Resolver: fixedIPResolver{
			err: errors.New("resolver unavailable"),
		},
	})

	target, err := dowurl.Normalize("http://scanner.test:8080/")
	require.NoError(t, err)

	_, err = client.Fetch(context.Background(), target)

	require.ErrorIs(t, err, types.ErrUnreachable)
}

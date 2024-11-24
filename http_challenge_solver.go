package acme

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"maps"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"go.n16f.net/log"
)

type HTTPChallengeSolverCfg struct {
	Log               *log.Logger `json:"-"`
	AccountThumbprint string      `json:"-"`

	Address     string `json:"address"`
	UpstreamURI string `json:"upstream_uri,omitempty"`
}

type HTTPChallengeSolver struct {
	Cfg HTTPChallengeSolverCfg
	Log *log.Logger

	httpServer        *http.Server
	accountThumbprint string
	challenges        map[string]struct{}
	challengesMutex   sync.Mutex

	upstreamURI    *url.URL
	upstreamConn   net.Conn
	upstreamReader *bufio.Reader
	upstreamMutex  sync.Mutex

	wg sync.WaitGroup
}

func NewHTTPChallengeSolver(cfg HTTPChallengeSolverCfg) (*HTTPChallengeSolver, error) {
	if cfg.Address == "" {
		// Usually we default to localhost for default server addresses, but the
		// very point of the HTTP challenge solver is to be available from an
		// external ACME server.
		cfg.Address = "0.0.0.0:80"
	}

	logger := cfg.Log.Child("http_solver", nil)

	s := HTTPChallengeSolver{
		Cfg: cfg,
		Log: logger,

		challenges: make(map[string]struct{}),
	}

	s.httpServer = &http.Server{
		Addr:     cfg.Address,
		Handler:  &s,
		ErrorLog: logger.StdLogger(log.LevelError),

		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       10 * time.Second,
	}

	if cfg.UpstreamURI != "" {
		uri, err := url.Parse(cfg.UpstreamURI)
		if err != nil {
			return nil, fmt.Errorf("cannot parse upstream URI: %w", err)
		}

		if uri.Scheme == "" {
			uri.Scheme = "http"
		}
		if uri.Host == "" {
			uri.Host = "localhost"
		}
		uri.Path = ""
		uri.Fragment = ""

		s.upstreamURI = uri
	}

	return &s, nil
}

func (s *HTTPChallengeSolver) Start(accountThumbprint string) error {
	s.accountThumbprint = accountThumbprint

	if s.upstreamURI != nil {
		s.Log.Info("forwarding non-ACME HTTP requests to %q", s.Cfg.UpstreamURI)

		// We do not really have to connect to the upstream server until the
		// first request, but doing so helps catching configuration errors
		// early.
		if err := s.ensureUpstreamConnection(); err != nil {
			return err
		}
	}

	listener, err := net.Listen("tcp", s.Cfg.Address)
	if err != nil {
		return fmt.Errorf("cannot listen on %q: %w", s.Cfg.Address, err)
	}

	s.Log.Info("HTTP challenge solver listening on %q", s.Cfg.Address)

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()

		if err := s.httpServer.Serve(listener); err != nil {
			if err != http.ErrServerClosed {
				s.Log.Error("HTTP server error: %v", err)
			}
		}
	}()

	return nil
}

func (s *HTTPChallengeSolver) Stop() {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	if err := s.httpServer.Shutdown(ctx); err != nil {
		s.Log.Error("cannot shutdown server: %v", err)
	}

	s.wg.Wait()

	s.upstreamMutex.Lock()
	if s.upstreamConn != nil {
		s.upstreamConn.Close()
		s.upstreamConn = nil
	}
	s.upstreamMutex.Unlock()
}

func (s *HTTPChallengeSolver) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	token, found := strings.CutPrefix(req.URL.Path,
		"/.well-known/acme-challenge/")
	if found {
		s.hChallenge(w, req, token)
		return
	}

	if s.upstreamURI == nil {
		w.WriteHeader(404)
		return
	}

	s.upstreamMutex.Lock()
	defer s.upstreamMutex.Unlock()

	if err := s.ensureUpstreamConnection(); err != nil {
		s.Log.Error("%v", err)
		w.WriteHeader(500)
		return
	}

	res, err := s.sendUpstreamRequest(req)
	if err != nil {
		s.Log.Error("cannot forward request to upstream server: %v", err)
		s.upstreamConn.Close()
		s.upstreamConn = nil
		w.WriteHeader(500)
		return
	}
	defer res.Body.Close()

	maps.Copy(w.Header(), res.Header)
	w.WriteHeader(res.StatusCode)

	if _, err := io.Copy(w, res.Body); err != nil {
		s.Log.Error("cannot copy response body: %v", err)
		s.upstreamConn.Close()
		s.upstreamConn = nil
		return
	}
}

func (s *HTTPChallengeSolver) sendUpstreamRequest(req *http.Request) (*http.Response, error) {
	req = req.Clone(context.Background())

	// In a regular reverse proxy we would rewrite the scheme and host of the
	// request to match the URI of the upstream server. However here the
	// upstream server will be expecting requests from the outside world, not
	// from localhost. The very point of this reverse proxy is to be
	// transparent.
	//
	// However we still have to remove hop-by-hop header fields (RFC 2616
	// 13.5.1) because they could make the upstream server behave incorrectly.
	var rfc2616Fields = []string{
		"Connection",
		"Keep-Alive",
		"Proxy-Authenticate",
		"Proxy-Authorization",
		"TE",
		"Trailers",
		"Transfer-Encoding",
		"Upgrade",
	}

	for _, name := range rfc2616Fields {
		req.Header.Del(name)
	}

	if err := req.Write(s.upstreamConn); err != nil {
		return nil, fmt.Errorf("cannot write request: %w", err)
	}

	res, err := http.ReadResponse(s.upstreamReader, req)
	if err != nil {
		return nil, fmt.Errorf("cannot read response: %w", err)
	}

	return res, nil
}

func (s *HTTPChallengeSolver) ensureUpstreamConnection() error {
	if s.upstreamConn != nil {
		return nil
	}

	conn, err := net.Dial("tcp", s.upstreamURI.Host)
	if err != nil {
		return fmt.Errorf("cannot connect to %q: %w", s.upstreamURI.Host, err)
	}

	s.upstreamConn = conn
	s.upstreamReader = bufio.NewReader(conn)

	return nil
}

func (s *HTTPChallengeSolver) addToken(token string) {
	s.challengesMutex.Lock()
	s.challenges[token] = struct{}{}
	s.challengesMutex.Unlock()
}

func (s *HTTPChallengeSolver) discardToken(token string) {
	s.challengesMutex.Lock()
	delete(s.challenges, token)
	s.challengesMutex.Unlock()
}

func (s *HTTPChallengeSolver) hChallenge(w http.ResponseWriter, req *http.Request, token string) {
	var statusCode int
	reply := func(status int, format string, args ...any) {
		statusCode = status
		w.WriteHeader(status)
		fmt.Fprintf(w, format+"\n", args...)
	}

	defer func() {
		statusString := "-"
		if statusCode > 0 {
			statusString = strconv.Itoa(statusCode)
		}

		s.Log.Debug(2, "%s %s %s", req.Method, req.URL.String(), statusString)
	}()

	s.challengesMutex.Lock()
	defer s.challengesMutex.Unlock()

	if _, found := s.challenges[token]; !found {
		reply(400, "unknown token")
		return
	}

	// RFC 8555 8.3. HTTP Challenge: "A client fulfills this challenge by
	// constructing a key authorization from the "token" value provided in the
	// challenge and the client's account key". Do not ask what format should
	// one use for the "client's account key" or how it is supposed to be
	// combined with the token. Because hey, who cares about these details
	// right? So let us just do what other solvers do...

	reply(200, "%s.%s", token, s.accountThumbprint)
}

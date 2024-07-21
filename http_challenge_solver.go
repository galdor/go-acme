package acme

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"go.n16f.net/log"
)

type HTTPChallengeSolverCfg struct {
	Log               *log.Logger `json:"-"`
	AccountThumbprint string      `json:"-"`

	Address string `json:"address"`
}

type HTTPChallengeSolver struct {
	Cfg HTTPChallengeSolverCfg
	Log *log.Logger

	httpServer        *http.Server
	accountThumbprint string
	challenges        map[string]struct{}
	challengesMutex   sync.Mutex

	wg sync.WaitGroup
}

func NewHTTPChallengeSolver(cfg HTTPChallengeSolverCfg) *HTTPChallengeSolver {
	if cfg.Address == "" {
		// Usually we default to localhost for default server addresses, but the
		// very point of the HTTP challenge solver is to be available from an
		// external ACME server.
		cfg.Address = "0.0.0.0:80"
	}

	httpMux := http.NewServeMux()

	logger := cfg.Log.Child("http_solver", nil)

	httpServer := http.Server{
		Addr:     cfg.Address,
		Handler:  httpMux,
		ErrorLog: logger.StdLogger(log.LevelError),

		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       10 * time.Second,
	}

	s := HTTPChallengeSolver{
		Cfg: cfg,
		Log: logger,

		challenges: make(map[string]struct{}),

		httpServer: &httpServer,
	}

	httpMux.HandleFunc("/", s.hNotFound)
	httpMux.HandleFunc("/.well-known/acme-challenge/{token}", s.hChallenge)

	return &s
}

func (s *HTTPChallengeSolver) Start(accountThumbprint string) error {
	s.accountThumbprint = accountThumbprint

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

func (s *HTTPChallengeSolver) hNotFound(w http.ResponseWriter, req *http.Request) {
	w.WriteHeader(404)
}

func (s *HTTPChallengeSolver) hChallenge(w http.ResponseWriter, req *http.Request) {
	token := req.PathValue("token")

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

package acme

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"
)

type HTTPChallengeSolverCfg struct {
	Log               Logger `json:"-"`
	AccountThumbprint string `json:"-"`

	Address string `json:"address"`
}

type HTTPChallengeSolver struct {
	Cfg HTTPChallengeSolverCfg
	Log Logger

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

	httpServer := http.Server{
		Addr:     cfg.Address,
		Handler:  httpMux,
		ErrorLog: NewStdErrorLogger(cfg.Log),

		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       10 * time.Second,
	}

	s := HTTPChallengeSolver{
		Cfg: cfg,
		Log: cfg.Log,

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
				// TODO Retry?
				s.Log.Error("cannot serve: %v", err)
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

	s.challengesMutex.Lock()
	defer s.challengesMutex.Unlock()

	if _, found := s.challenges[token]; !found {
		w.WriteHeader(400)
		fmt.Fprintf(w, "unknown token\n")
		return
	}

	// RFC 8555 8.3. HTTP Challenge: "A client fulfills this challenge by
	// constructing a key authorization from the "token" value provided in the
	// challenge and the client's account key". Do not ask what format should
	// one use for the "client's account key" or how it is supposed to be
	// combined with the token. Because hey, who cares about these details
	// right? So let us just do what other solvers do...

	w.WriteHeader(200)
	fmt.Fprintf(w, "%s.%s", token, s.accountThumbprint)
}

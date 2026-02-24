package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"time"

	"github.com/ndbaker1/regi/registry"
	"github.com/ndbaker1/regi/store"
)

const (
	// defaultAddr is the default listen address for the registry server.
	defaultAddr = ":5000"

	// defaultLogLevel is the default logging level.
	defaultLogLevel = "debug"

	// serverReadTimeout is the maximum duration for reading the entire request.
	serverReadTimeout = 30 * time.Second

	// serverWriteTimeout is the maximum duration for writing the response.
	// Set high to accommodate large blob transfers.
	serverWriteTimeout = 5 * time.Minute

	// serverIdleTimeout is the maximum duration to wait for the next request
	// on a keep-alive connection.
	serverIdleTimeout = 120 * time.Second

	// shutdownTimeout is the maximum duration to wait for in-flight requests
	// to complete during graceful shutdown.
	shutdownTimeout = 10 * time.Second
)

var (
	addr     string
	logLevel string
)

func init() {
	// parse flags as a pre-setup before main.
	flag.StringVar(&addr, "addr", defaultAddr, "listen address")
	flag.StringVar(&logLevel, "log-level", defaultLogLevel, "log level (debug, info, warn, error)")
	flag.Parse()
}

func main() {
	logger := newLogger()

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	s, err := store.NewDockerClient(ctx)
	if err != nil {
		logger.Error("failed to connect to store", "error", err)
		os.Exit(1)
	}

	srv := &http.Server{
		Addr:         addr,
		Handler:      registry.New(store.NewStore(s, logger), logger),
		ReadTimeout:  serverReadTimeout,
		WriteTimeout: serverWriteTimeout,
		IdleTimeout:  serverIdleTimeout,
	}

	go func() {
		logger.Info("starting registry", "addr", addr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("server error", "error", err)
			os.Exit(1)
		}
	}()

	<-ctx.Done()
	logger.Info("shutting down")

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer shutdownCancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		logger.Error("shutdown error", "error", err)
	}
}

func newLogger() *slog.Logger {
	var level slog.Level
	switch logLevel {
	case "debug":
		level = slog.LevelDebug
	case "info":
		level = slog.LevelInfo
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		fmt.Fprintf(os.Stderr, "unknown log level: %s\n", logLevel)
		os.Exit(1)
	}
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))
}

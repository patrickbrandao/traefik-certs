package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/patrickbrandao/traefik-certs/internal/certstore"
	"github.com/patrickbrandao/traefik-certs/internal/config"
	"github.com/patrickbrandao/traefik-certs/internal/reconcile"
	"github.com/patrickbrandao/traefik-certs/internal/redisbus"
)

func main() {
	// Configure a minimal JSON logger before config.Load() so that boot errors
	// are already structured (item 3.7). The level will be reconfigured below
	// after the config is available.
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo})))

	cfg, err := config.Load()
	if err != nil {
		slog.Error("config error", "error", err.Error())
		os.Exit(1)
	}

	// Reconfigure logger with the level requested by the operator.
	level := slog.LevelInfo
	switch cfg.LogLevel {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	}
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: level})))

	slog.Info("cert-watcher starting",
		"node_id", cfg.NodeID,
		"save_dir", cfg.SaveDir,
		"acme_path", cfg.AcmeJSONPath,
		"redis_configured", cfg.RedisURL != "",
	)

	if cfg.AcmeJSONPath == "" {
		slog.Warn("no acme directory found, will keep trying",
			"node_id", cfg.NodeID,
		)
	}

	store := certstore.New(cfg.SaveDir)
	table := reconcile.NewSourceTable()
	if err := table.LoadFromDisk(store); err != nil {
		slog.Warn("failed to load source table from disk",
			"error", err.Error(),
			"node_id", cfg.NodeID,
		)
	}

	// Try to connect to Redis. A failure is not fatal: we start in local mode
	// and a background watchdog will reconnect (SPEC §13, items 2.1 + 2.5).
	var bus *redisbus.Bus
	if cfg.RedisURL != "" {
		bus, err = redisbus.New(cfg.RedisURL, cfg.RedisPrefix)
		if err != nil {
			slog.Warn("redis connection failed, starting in local mode",
				"error", err.Error(),
				"node_id", cfg.NodeID,
			)
			bus = nil
		} else {
			slog.Info("redis connected",
				"node_id", cfg.NodeID,
			)
		}
	}

	rec := reconcile.New(cfg, store, bus, table)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	rec.SyncCerts(ctx)
	rec.StartSubscriber(ctx)

	// If boot-time Redis connection failed, start a watchdog that retries in
	// the background and, on success, registers the new bus and runs a full
	// sync_redis (item 2.5).
	if cfg.RedisURL != "" && bus == nil {
		go startRedisWatchdog(ctx, cfg, rec)
	}

	// Polling loop: WaitAndContinue respects ctx so shutdown is immediate (item 1.3).
	go func() {
		for {
			if !reconcile.WaitAndContinue(ctx, cfg.AcmeInterval) {
				return
			}
			rec.SyncCerts(ctx)
		}
	}()

	sig := <-sigCh
	slog.Info("received signal, shutting down",
		"signal", sig.String(),
		"node_id", cfg.NodeID,
	)
	cancel()

	// Wait for in-flight hook goroutines before closing (item 1.4).
	rec.Wait()
	rec.CloseBus()

	slog.Info("cert-watcher stopped",
		"node_id", cfg.NodeID,
	)
}

// startRedisWatchdog retries connecting to Redis with exponential backoff.
// When a connection is established it registers the bus in rec, starts the
// subscriber, and runs a full SyncRedis to catch up on any events missed while
// operating in local mode (SPEC §13, item 2.5).
func startRedisWatchdog(ctx context.Context, cfg *config.Config, rec *reconcile.Reconcile) {
	backoff := 5 * time.Second
	const maxBackoff = 60 * time.Second

	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}

		b, err := redisbus.New(cfg.RedisURL, cfg.RedisPrefix)
		if err != nil {
			slog.Warn("redis reconnect attempt failed",
				"error", err.Error(),
				"node_id", cfg.NodeID,
				"next_retry", backoff.String(),
			)
			if backoff < maxBackoff {
				backoff *= 2
			}
			continue
		}

		slog.Info("redis reconnected",
			"node_id", cfg.NodeID,
		)
		rec.SetBus(b)
		rec.StartSubscriber(ctx)
		rec.SyncRedis(ctx)
		return
	}
}

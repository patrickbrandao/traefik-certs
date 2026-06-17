package reconcile

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/patrickbrandao/traefik-certs/internal/acme"
	"github.com/patrickbrandao/traefik-certs/internal/certmodel"
	"github.com/patrickbrandao/traefik-certs/internal/certstore"
	"github.com/patrickbrandao/traefik-certs/internal/config"
	"github.com/patrickbrandao/traefik-certs/internal/hooks"
	"github.com/patrickbrandao/traefik-certs/internal/redisbus"
)

// SourceTable tracks the origin of every certificate that has been written to
// disk. All methods are safe for concurrent use (item 1.1).
type SourceTable struct {
	mu      sync.RWMutex
	sources map[string]string
}

func NewSourceTable() *SourceTable {
	return &SourceTable{sources: make(map[string]string)}
}

func (st *SourceTable) LoadFromDisk(store *certstore.Store) error {
	fqdns, err := store.ScanFQDNs()
	if err != nil {
		return err
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	for _, fqdn := range fqdns {
		cj, err := store.ReadCertJSON(fqdn)
		if err != nil {
			if store.Exists(fqdn) {
				st.sources[fqdn] = "file"
			}
			continue
		}
		st.sources[fqdn] = cj.Source
		if st.sources[fqdn] == "" {
			st.sources[fqdn] = "file"
		}
	}
	return nil
}

func (st *SourceTable) Set(fqdn, source string) {
	st.mu.Lock()
	defer st.mu.Unlock()
	st.sources[fqdn] = source
}

func (st *SourceTable) Get(fqdn string) string {
	st.mu.RLock()
	defer st.mu.RUnlock()
	return st.sources[fqdn]
}

// Reconcile orchestrates ACME parsing, local cert writes, Redis push/pull,
// and event handling. The embedded bus field is protected by busMu so that
// a reconnect watchdog can call SetBus safely (item 2.1/2.5). hookWg tracks
// in-flight hook goroutines for graceful shutdown (item 1.4).
type Reconcile struct {
	cfg    *config.Config
	store  *certstore.Store
	busMu  sync.RWMutex
	bus    *redisbus.Bus
	table  *SourceTable
	hookWg sync.WaitGroup
}

func New(cfg *config.Config, store *certstore.Store, bus *redisbus.Bus, table *SourceTable) *Reconcile {
	return &Reconcile{
		cfg:   cfg,
		store: store,
		bus:   bus,
		table: table,
	}
}

// getBus returns the current bus in a thread-safe manner.
func (r *Reconcile) getBus() *redisbus.Bus {
	r.busMu.RLock()
	defer r.busMu.RUnlock()
	return r.bus
}

// SetBus replaces the active bus (e.g. after a successful reconnect).
func (r *Reconcile) SetBus(bus *redisbus.Bus) {
	r.busMu.Lock()
	defer r.busMu.Unlock()
	r.bus = bus
}

// CloseBus stops and closes the active bus, if any.
func (r *Reconcile) CloseBus() {
	r.busMu.Lock()
	bus := r.bus
	r.busMu.Unlock()
	if bus != nil {
		bus.Close()
	}
}

// StartSubscriber subscribes to Redis events using the current bus.
// It is a no-op when no bus is configured.
func (r *Reconcile) StartSubscriber(ctx context.Context) {
	bus := r.getBus()
	if bus == nil {
		return
	}
	bus.Subscribe(ctx, func(fqdn string) {
		r.HandleRedisEvent(ctx, fqdn)
	})
}

// Wait blocks until all in-flight hook goroutines have finished.
// Call this during graceful shutdown (item 1.4).
func (r *Reconcile) Wait() {
	r.hookWg.Wait()
}

func (r *Reconcile) SyncCerts(ctx context.Context) {
	slog.Info("sync_certs start",
		"component", "sync_certs",
		"node_id", r.cfg.NodeID,
	)

	if r.cfg.AcmeJSONPath == "" {
		slog.Warn("sync_certs skip, acme path not available",
			"component", "sync_certs",
			"node_id", r.cfg.NodeID,
		)
		return
	}

	entries, err := acme.ParseACME(r.cfg.AcmeJSONPath)
	if err != nil {
		slog.Warn("sync_certs skip, cannot parse acme.json",
			"component", "sync_certs",
			"path", r.cfg.AcmeJSONPath,
			"error", err.Error(),
			"node_id", r.cfg.NodeID,
		)
		return
	}

	slog.Debug("sync_certs parsed entries",
		"component", "sync_certs",
		"count", len(entries),
		"node_id", r.cfg.NodeID,
	)

	dedup := make(map[string]*acme.AcmeEntry)
	for i, e := range entries {
		dedup[e.FQDN] = &entries[i]
	}

	updates := make(map[string]*certmodel.CertJSON)

	for fqdn, entry := range dedup {
		cj, err := certmodel.BuildCertJSON(fqdn, entry.SANs, entry.FullchainPEM, entry.PrivkeyPEM, "acme", entry.Resolver)
		if err != nil {
			slog.Error("sync_certs build cert",
				"component", "sync_certs",
				"fqdn", fqdn,
				"error", err.Error(),
				"node_id", r.cfg.NodeID,
			)
			continue
		}

		unlock := r.store.Lock(fqdn)
		func() {
			defer unlock()
			local, _ := r.store.ReadCertJSON(fqdn)

			shouldWrite := false
			if local == nil {
				shouldWrite = true
			} else if cj.NotAfterUnix > local.NotAfterUnix {
				shouldWrite = true
			} else if cj.NotAfterUnix == local.NotAfterUnix && cj.Hash.Cert != local.Hash.Cert {
				shouldWrite = true
			}

			if !shouldWrite {
				slog.Debug("sync_certs skip",
					"component", "sync_certs",
					"fqdn", fqdn,
					"action", "skip",
					"node_id", r.cfg.NodeID,
				)
				return
			}

			if err := r.store.WriteCertFiles(fqdn, cj); err != nil {
				slog.Error("sync_certs write files",
					"component", "sync_certs",
					"fqdn", fqdn,
					"error", err.Error(),
					"node_id", r.cfg.NodeID,
				)
				return
			}

			r.table.Set(fqdn, "acme")
			updates[fqdn] = cj

			slog.Info("sync_certs write",
				"component", "sync_certs",
				"fqdn", fqdn,
				"action", "write",
				"source", "acme",
				"not_after", cj.NotAfter,
				"node_id", r.cfg.NodeID,
			)
		}()
	}

	// Dispatch hook goroutines, tracked by hookWg for graceful shutdown (item 1.4).
	// RunHook1 and RunHook2 both receive ctx so they honour cancellation (items 1.5, 1.6).
	for fqdn, cj := range updates {
		r.hookWg.Add(1)
		go func(f string, c *certmodel.CertJSON) {
			defer r.hookWg.Done()
			dir := r.store.FQDNPath(f)
			hooks.RunHook1(ctx, r.cfg, f, dir)
			hooks.RunHook2(ctx, r.cfg, &r.hookWg, c)
		}(fqdn, cj)
	}

	slog.Info("sync_certs done",
		"component", "sync_certs",
		"updates", len(updates),
		"node_id", r.cfg.NodeID,
	)

	if r.getBus() != nil {
		r.SyncRedis(ctx)
	}
}

func (r *Reconcile) SyncRedis(ctx context.Context) {
	bus := r.getBus()
	if bus == nil {
		return
	}

	slog.Info("sync_redis start",
		"component", "sync_redis",
		"node_id", r.cfg.NodeID,
	)

	if err := bus.Ping(ctx); err != nil {
		slog.Warn("sync_redis redis unavailable",
			"component", "sync_redis",
			"error", err.Error(),
			"node_id", r.cfg.NodeID,
		)
		return
	}

	// PULL: learn certs from Redis that are newer than local copies.
	redisFQDNs, err := bus.GetAllCertKeys(ctx)
	if err != nil {
		slog.Warn("sync_redis scan failed",
			"component", "sync_redis",
			"error", err.Error(),
			"node_id", r.cfg.NodeID,
		)
	} else {
		for _, fqdn := range redisFQDNs {
			remote, err := bus.GetCert(ctx, fqdn)
			if err != nil || remote == nil {
				continue
			}

			unlock := r.store.Lock(fqdn)
			func() {
				defer unlock()

				local, _ := r.store.ReadCertJSON(fqdn)

				shouldWrite := false
				if local == nil {
					shouldWrite = true
				} else if remote.NotAfterUnix > local.NotAfterUnix {
					shouldWrite = true
				}

				if !shouldWrite {
					return
				}

				remote.Source = "redis"
				if err := r.store.WriteCertFiles(fqdn, remote); err != nil {
					slog.Error("sync_redis write pull",
						"component", "sync_redis",
						"fqdn", fqdn,
						"error", err.Error(),
						"node_id", r.cfg.NodeID,
					)
					return
				}

				r.table.Set(fqdn, "redis")

				slog.Info("sync_redis learn",
					"component", "sync_redis",
					"fqdn", fqdn,
					"action", "learn",
					"source", "redis",
					"not_after", remote.NotAfter,
					"node_id", r.cfg.NodeID,
				)
			}()
		}
	}

	// PUSH: publish local certs that are newer than what Redis has.
	localFQDNs, err := r.store.ScanFQDNs()
	if err != nil {
		slog.Warn("sync_redis scan local failed",
			"component", "sync_redis",
			"error", err.Error(),
			"node_id", r.cfg.NodeID,
		)
	} else {
		for _, fqdn := range localFQDNs {
			source := r.table.Get(fqdn)
			if source == "redis" {
				continue
			}

			local, err := r.store.ReadCertJSON(fqdn)
			if err != nil || local == nil {
				continue
			}

			remote, _ := bus.GetCert(ctx, fqdn)

			if remote != nil && local.NotAfterUnix <= remote.NotAfterUnix {
				continue
			}

			if remote != nil && remote.CertMD5 == local.CertMD5 {
				continue
			}

			if err := bus.SetCert(ctx, fqdn, local); err != nil {
				slog.Error("sync_redis set",
					"component", "sync_redis",
					"fqdn", fqdn,
					"error", err.Error(),
					"node_id", r.cfg.NodeID,
				)
				continue
			}

			if err := bus.PublishEvent(ctx, fqdn); err != nil {
				slog.Error("sync_redis publish",
					"component", "sync_redis",
					"fqdn", fqdn,
					"error", err.Error(),
					"node_id", r.cfg.NodeID,
				)
				continue
			}

			slog.Info("sync_redis push",
				"component", "sync_redis",
				"fqdn", fqdn,
				"action", "publish",
				"not_after", local.NotAfter,
				"node_id", r.cfg.NodeID,
			)
		}
	}

	slog.Info("sync_redis done",
		"component", "sync_redis",
		"node_id", r.cfg.NodeID,
	)
}

func (r *Reconcile) HandleRedisEvent(ctx context.Context, fqdn string) {
	bus := r.getBus()
	if bus == nil {
		return
	}

	remote, err := bus.GetCert(ctx, fqdn)
	if err != nil || remote == nil {
		slog.Warn("subscriber get cert",
			"component", "subscriber",
			"fqdn", fqdn,
			"error", func() string {
				if err != nil {
					return err.Error()
				}
				return "not found"
			}(),
			"node_id", r.cfg.NodeID,
		)
		return
	}

	unlock := r.store.Lock(fqdn)
	defer unlock()

	local, _ := r.store.ReadCertJSON(fqdn)

	shouldWrite := false
	if local == nil {
		shouldWrite = true
	} else if remote.NotAfterUnix > local.NotAfterUnix {
		shouldWrite = true
	}

	if !shouldWrite {
		return
	}

	remote.Source = "redis"
	if err := r.store.WriteCertFiles(fqdn, remote); err != nil {
		slog.Error("subscriber write",
			"component", "subscriber",
			"fqdn", fqdn,
			"error", err.Error(),
			"node_id", r.cfg.NodeID,
		)
		return
	}

	r.table.Set(fqdn, "redis")

	slog.Info("subscriber learn",
		"component", "subscriber",
		"fqdn", fqdn,
		"action", "learn",
		"source", "redis",
		"not_after", remote.NotAfter,
		"node_id", r.cfg.NodeID,
	)
}

// WaitAndContinue sleeps for interval and returns true, or returns false
// immediately if ctx is cancelled. This allows the polling loop to respect
// graceful shutdown without blocking for the full interval (item 1.3).
func WaitAndContinue(ctx context.Context, interval time.Duration) bool {
	select {
	case <-ctx.Done():
		return false
	case <-time.After(interval):
		return true
	}
}

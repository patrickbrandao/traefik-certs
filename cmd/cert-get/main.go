package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"

	"github.com/patrickbrandao/traefik-certs/internal/certmodel"
	"github.com/patrickbrandao/traefik-certs/internal/certstore"
	"github.com/patrickbrandao/traefik-certs/internal/config"
	"github.com/patrickbrandao/traefik-certs/internal/redisbus"
)

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: cert-get <FQDN> <DEST_DIR>")
		os.Exit(1)
	}

	fqdn := os.Args[1]
	destDir := os.Args[2]

	if _, err := os.Stat(destDir); os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "destination directory does not exist: %s\n", destDir)
		os.Exit(1)
	}

	// Configure a minimal JSON logger before config.Load() so that boot errors
	// are already structured (item 3.7).
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo})))

	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "config error: %v\n", err)
		os.Exit(1)
	}

	// Reconfigure with the operator-requested log level.
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

	var bus *redisbus.Bus
	if cfg.RedisURL != "" {
		bus, err = redisbus.New(cfg.RedisURL, cfg.RedisPrefix)
		if err != nil {
			slog.Warn("redis unavailable, using local only",
				"component", "cert-get",
				"error", err.Error(),
			)
			bus = nil
		}
	}

	store := certstore.New(cfg.SaveDir)
	cert, source, err := findBestCert(context.Background(), store, bus, fqdn)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error finding certificate for %s: %v\n", fqdn, err)
		os.Exit(1)
	}
	if cert == nil {
		fmt.Fprintf(os.Stderr, "no valid certificate found for %s\n", fqdn)
		os.Exit(1)
	}

	if err := store.WriteCertFilesFlat(destDir, cert); err != nil {
		fmt.Fprintf(os.Stderr, "error writing certificate files to %s: %v\n", destDir, err)
		os.Exit(1)
	}

	fmt.Printf("fqdn=%s source=%s not_after=%s\n", fqdn, source, cert.NotAfter)
}

func findBestCert(ctx context.Context, store *certstore.Store, bus *redisbus.Bus, targetFQDN string) (*certmodel.CertJSON, string, error) {
	var best *certmodel.CertJSON
	var bestSource string
	bestMatchType := "" // "exact" or "wildcard"

	checkCert := func(cj *certmodel.CertJSON, source string) {
		if cj == nil {
			return
		}
		if !cj.IsValidNow() {
			return
		}

		matchType := ""
		if cj.MatchesExact(targetFQDN) {
			matchType = "exact"
		} else if cj.CoversWildcard(targetFQDN) {
			matchType = "wildcard"
		} else {
			return
		}

		// Prefer exact over wildcard
		if best != nil && bestMatchType == "exact" && matchType == "wildcard" {
			return
		}
		if best != nil && bestMatchType == "wildcard" && matchType == "exact" {
			best = cj
			bestSource = source
			bestMatchType = matchType
			return
		}

		if best == nil || cj.NotAfterUnix > best.NotAfterUnix {
			best = cj
			bestSource = source
			bestMatchType = matchType
		}
	}

	// Check local disk
	fqdns, err := store.ScanFQDNs()
	if err == nil {
		for _, candidate := range fqdns {
			cj, err := store.ReadCertJSON(candidate)
			if err != nil {
				continue
			}
			checkCert(cj, "local")
		}
	}

	// Check Redis
	if bus != nil {
		redisFQDNs, err := bus.GetAllCertKeys(ctx)
		if err == nil {
			for _, candidate := range redisFQDNs {
				cj, err := bus.GetCert(ctx, candidate)
				if err != nil || cj == nil {
					continue
				}
				checkCert(cj, "redis")
			}
		}
	}

	if best != nil && bestSource == "" {
		bestSource = "local"
	}

	if best == nil && bus != nil {
		// Last-resort: look up by sanitized wildcard key directly.
		sanitized := certmodel.SanitizeFQDN(targetFQDN)
		cj, err := bus.GetCert(ctx, sanitized)
		if err == nil && cj != nil {
			checkCert(cj, "redis")
		}
	}

	return best, bestSource, nil
}

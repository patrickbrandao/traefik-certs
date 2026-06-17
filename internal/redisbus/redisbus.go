package redisbus

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/patrickbrandao/traefik-certs/internal/certmodel"
	"github.com/redis/go-redis/v9"
)

// Bus wraps a Redis client and exposes cert pub/sub operations.
type Bus struct {
	client *redis.Client
	prefix string
	mu     sync.Mutex      // protects cancel
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

func New(redisURL, prefix string) (*Bus, error) {
	opts, err := redis.ParseURL(redisURL)
	if err != nil {
		return nil, fmt.Errorf("parse redis URL: %w", err)
	}
	client := redis.NewClient(opts)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := client.Ping(ctx).Err(); err != nil {
		client.Close()
		return nil, fmt.Errorf("redis ping: %w", err)
	}
	return &Bus{
		client: client,
		prefix: prefix,
	}, nil
}

// Close stops the subscriber goroutine (if running) and waits for it to exit,
// then closes the underlying Redis connection.
func (b *Bus) Close() {
	b.mu.Lock()
	if b.cancel != nil {
		b.cancel()
	}
	b.mu.Unlock()
	b.wg.Wait()
	b.client.Close()
}

func (b *Bus) Ping(ctx context.Context) error {
	return b.client.Ping(ctx).Err()
}

func (b *Bus) certKey(fqdn string) string {
	return fmt.Sprintf("%s:cert:%s", b.prefix, fqdn)
}

func (b *Bus) eventsChannel() string {
	return fmt.Sprintf("%s:events", b.prefix)
}

func (b *Bus) SetCert(ctx context.Context, fqdn string, cj *certmodel.CertJSON) error {
	data, err := json.Marshal(cj)
	if err != nil {
		return fmt.Errorf("marshal cert: %w", err)
	}
	return b.client.Set(ctx, b.certKey(fqdn), data, 0).Err()
}

func (b *Bus) GetCert(ctx context.Context, fqdn string) (*certmodel.CertJSON, error) {
	data, err := b.client.Get(ctx, b.certKey(fqdn)).Bytes()
	if err == redis.Nil {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var cj certmodel.CertJSON
	if err := json.Unmarshal(data, &cj); err != nil {
		return nil, fmt.Errorf("unmarshal cert: %w", err)
	}
	return &cj, nil
}

// GetAllCertKeys returns all FQDNs stored in Redis under the bus prefix.
func (b *Bus) GetAllCertKeys(ctx context.Context) ([]string, error) {
	pattern := fmt.Sprintf("%s:cert:*", b.prefix)
	certPrefix := b.prefix + ":cert:"
	var keys []string
	var cursor uint64
	for {
		var batch []string
		var err error
		batch, cursor, err = b.client.Scan(ctx, cursor, pattern, 100).Result()
		if err != nil {
			return nil, err
		}
		for _, key := range batch {
			// Use TrimPrefix to avoid brittle magic offsets (item 3.4).
			fqdn := strings.TrimPrefix(key, certPrefix)
			keys = append(keys, fqdn)
		}
		if cursor == 0 {
			break
		}
	}
	return keys, nil
}

func (b *Bus) PublishEvent(ctx context.Context, fqdn string) error {
	return b.client.Publish(ctx, b.eventsChannel(), fqdn).Err()
}

// Subscribe starts the subscriber goroutine in the background.
// An inner context derived from ctx is created and its cancel function is
// stored in b.cancel, so that Close() can stop the goroutine independently
// of the caller's context lifecycle (item 1.2).
func (b *Bus) Subscribe(ctx context.Context, handler func(fqdn string)) {
	innerCtx, cancel := context.WithCancel(ctx)

	b.mu.Lock()
	b.cancel = cancel
	b.mu.Unlock()

	b.wg.Add(1)
	go func() {
		defer b.wg.Done()
		defer cancel()
		for {
			select {
			case <-innerCtx.Done():
				return
			default:
			}
			pubsub := b.client.Subscribe(innerCtx, b.eventsChannel())
			ch := pubsub.Channel()
		loop:
			for {
				select {
				case <-innerCtx.Done():
					pubsub.Close()
					return
				case msg, ok := <-ch:
					if !ok {
						break loop
					}
					handler(msg.Payload)
				}
			}
			pubsub.Close()
			select {
			case <-innerCtx.Done():
				return
			case <-time.After(time.Second):
			}
		}
	}()
}

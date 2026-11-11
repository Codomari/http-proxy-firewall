package monitoring

import (
	"context"
	"os"
	"reflect"
	"strconv"
	"testing"
	"time"

	"http-proxy-firewall/internal/config"
	"http-proxy-firewall/internal/storage"

	"github.com/redis/go-redis/v9"
)

func TestCounterPersistenceWithRedisRestart(t *testing.T) {
	address := os.Getenv("PF_TEST_REDIS_ADDRESS")
	if address == "" {
		t.Skip("set PF_TEST_REDIS_ADDRESS to a disposable Redis instance")
	}
	key := "PF:TEST:COUNTERS:" + strconv.FormatInt(time.Now().UnixNano(), 36)
	cfg := config.Defaults()
	cfg.Admin.Enabled, cfg.Admin.MaxHosts = true, 300
	cfg.Redis.Enabled, cfg.Redis.Address, cfg.Redis.Timeout = true, address, time.Second
	// Only delete keys belonging to this test, including both bounded banks.
	cleanup := redis.NewClient(&redis.Options{Addr: address})
	defer cleanup.Close()
	defer func() {
		keys := []string{key}
		for bank := range 2 {
			for index := range 2 {
				keys = append(keys, counterChunkKey(key, bank, index))
			}
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := cleanup.Del(ctx, keys...).Err(); err != nil {
			t.Error(err)
		}
	}()
	start := func() (*Registry, *storage.Remote) {
		remote := storage.New(cfg, nil)
		if err := remote.Start(context.Background()); err != nil {
			t.Fatal(err)
		}
		r := New(cfg)
		r.ConfigurePersistence(remote, true, key, nil)
		if err := r.Start(context.Background()); err != nil {
			t.Fatal(err)
		}
		return r, remote
	}
	r, remote := start()
	populatePersistentCounters(r)
	wantTotals, wantHosts := r.Totals(), r.Hosts()
	if err := r.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	if r.CounterPersistence().LastSaved.IsZero() {
		t.Fatal("final snapshot was not committed to Redis")
	}
	if err := remote.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	restarted, remote := start()
	defer remote.Stop(context.Background())
	defer restarted.Stop(context.Background())
	if !restarted.CounterPersistence().Restored || !reflect.DeepEqual(restarted.Totals(), wantTotals) || !reflect.DeepEqual(restarted.Hosts(), wantHosts) {
		t.Fatalf("Redis restart lost counters: got=%+v want=%+v status=%+v", restarted.Totals(), wantTotals, restarted.CounterPersistence())
	}
}

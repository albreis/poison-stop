package store

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func TestRecordAndQuery(t *testing.T) {
	path := filepath.Join(t.TempDir(), "t.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	s.Record(Event{Time: now, Service: "app", ClientIP: "172.30.0.5", Host: "api.stripe.com", Port: 443, Proto: "https", BytesOut: 100, BytesIn: 2000})
	s.Record(Event{Time: now, Service: "app", ClientIP: "172.30.0.5", Host: "api.stripe.com", Port: 443, Proto: "https", BytesOut: 50, BytesIn: 10})
	s.Record(Event{Time: now, Service: "app", ClientIP: "172.30.0.5", Host: "evil.com", Port: 443, Proto: "https", Blocked: true})
	s.Record(Event{Time: now, Service: "worker", ClientIP: "172.30.0.6", Host: "example.com", Port: 80, Proto: "http"})
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	// reabre para garantir que os dados foram gravados em disco
	s, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()
	svcs, err := s.Services(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(svcs) != 2 {
		t.Fatalf("esperava 2 serviços, veio %d", len(svcs))
	}
	ds, err := s.Destinations(ctx, "app")
	if err != nil {
		t.Fatal(err)
	}
	if len(ds) != 2 {
		t.Fatalf("esperava 2 destinos, veio %d", len(ds))
	}
	if ds[0].Host != "api.stripe.com" || ds[0].Hits != 2 || ds[0].BytesOut != 150 || ds[0].BytesIn != 2010 {
		t.Errorf("agregado errado: %+v", ds[0])
	}
	if ds[1].Blocked != 1 {
		t.Errorf("evil.com deveria ter 1 bloqueio: %+v", ds[1])
	}
}

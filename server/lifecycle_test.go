package server

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestServerCloseWaitsForBackgroundWork(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	s := &Server{ctx: ctx, cancel: cancel, engine: NewEngine(nil)}
	started := make(chan struct{})
	release := make(chan struct{})
	if !s.goBackground(func() {
		close(started)
		<-s.ctx.Done()
		<-release
	}) {
		t.Fatal("background work was rejected before shutdown")
	}
	<-started
	closed := make(chan struct{})
	go func() {
		s.Close()
		close(closed)
	}()
	<-s.ctx.Done()
	select {
	case <-closed:
		t.Fatal("Close returned while background work was still active")
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("Close did not finish after background work exited")
	}
}

func TestEngineShutdownCancelsAndWaitsTaskRoutines(t *testing.T) {
	e := NewEngine(nil)
	rt := e.registerTaskRoutines(context.Background(), "task-1", 1)
	if !e.beginTaskOperation("task-2") {
		t.Fatal("task operation was rejected before shutdown")
	}
	started := make(chan struct{})
	runTaskRoutine(rt, func(ctx context.Context) {
		close(started)
		<-ctx.Done()
	})
	<-started
	shutdownDone := make(chan struct{})
	go func() {
		e.Shutdown()
		close(shutdownDone)
	}()
	select {
	case <-shutdownDone:
		t.Fatal("shutdown returned while an admitted task operation was still active")
	case <-time.After(20 * time.Millisecond):
	}
	e.decInflight("task-2")
	select {
	case <-shutdownDone:
	case <-time.After(time.Second):
		t.Fatal("shutdown did not finish after the task operation exited")
	}

	e.runtimeMu.Lock()
	runtimeCount := len(e.runtimes)
	e.runtimeMu.Unlock()
	if runtimeCount != 0 {
		t.Fatalf("task runtimes remain after shutdown: %d", runtimeCount)
	}
	if rt := e.registerTaskRoutines(context.Background(), "task-2", 1); rt != nil {
		t.Fatal("shutdown engine accepted a new runtime")
	}
}

func TestRedactDeliveryPacketRemovesCredentialFields(t *testing.T) {
	packet := "POST /test?access_token=query-secret HTTP/1.1\r\nAuthorization: Bearer header-secret\r\nCookie: sid=cookie-secret\r\nContent-Type: application/json\r\n\r\n{\"password\":\"body-secret\",\"profile\":{\"api_key\":\"nested-secret\"}}"
	redacted := redactDeliveryPacket(packet)
	for _, secret := range []string{"query-secret", "header-secret", "cookie-secret", "body-secret", "nested-secret"} {
		if strings.Contains(redacted, secret) {
			t.Errorf("redacted packet retains %q: %s", secret, redacted)
		}
	}
	for _, marker := range []string{redactedDeliveryValue, "POST /test?"} {
		if !strings.Contains(redacted, marker) {
			t.Errorf("redacted packet omitted %q: %s", marker, redacted)
		}
	}
}

package server

import (
	"sync"

	"github.com/wpsec/ARTEX-local/agent"
)

func (s *Server) goBackground(fn func()) bool {
	return s.goBackgroundWith(nil, fn)
}

func (s *Server) goBackgroundWith(extra *sync.WaitGroup, fn func()) bool {
	s.lifecycleMu.Lock()
	if s.closing {
		s.lifecycleMu.Unlock()
		return false
	}
	s.backgroundWG.Add(1)
	if extra != nil {
		extra.Add(1)
	}
	s.lifecycleMu.Unlock()

	go func() {
		defer s.backgroundWG.Done()
		if extra != nil {
			defer extra.Done()
		}
		fn()
	}()
	return true
}

// Close cancels server-owned work and waits for database users before Manager
// closes the shared PostgreSQL pool.
func (s *Server) Close() {
	if s == nil {
		return
	}
	s.closeOnce.Do(func() {
		s.lifecycleMu.Lock()
		s.closing = true
		s.lifecycleMu.Unlock()
		if s.cancel != nil {
			s.cancel()
		}
		s.chatMu.Lock()
		for _, cancel := range s.chatCancel {
			cancel(agent.AbortShutdown)
		}
		s.chatMu.Unlock()
		if s.engine != nil {
			s.engine.Shutdown()
		}
		s.archiveWG.Wait()
		s.backgroundWG.Wait()
		if s.side != nil {
			<-s.side.done
		}
		if s.m != nil {
			s.m.unregisterServer(s)
		}
	})
}

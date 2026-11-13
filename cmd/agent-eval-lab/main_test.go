package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPositiveAndNegativeControls(t *testing.T) {
	l := &lab{counts: make(map[string]int)}
	for _, tc := range []struct {
		path  string
		actor string
		code  int
		body  string
	}{
		{"/api/a/records/2", "alpha", http.StatusOK, `"owner":"beta"`},
		{"/api/b/records/2", "alpha", http.StatusForbidden, "not authorized"},
		{"/api/b/records/2", "beta", http.StatusOK, `"owner":"beta"`},
		{"/api/a/records/2", "", http.StatusUnauthorized, "X-Lab-Actor"},
		{"/web/a?q=%3Cb%3Eprobe%3C%2Fb%3E", "", http.StatusOK, "<b>probe</b>"},
		{"/web/b?q=%3Cb%3Eprobe%3C%2Fb%3E", "", http.StatusOK, "&lt;b&gt;probe&lt;/b&gt;"},
	} {
		r := httptest.NewRequest(http.MethodGet, tc.path, nil)
		if tc.actor != "" {
			r.Header.Set("X-Lab-Actor", tc.actor)
		}
		w := httptest.NewRecorder()
		l.ServeHTTP(w, r)
		if w.Code != tc.code || !strings.Contains(w.Body.String(), tc.body) {
			t.Errorf("%s: status=%d body=%q", tc.path, w.Code, w.Body.String())
		}
	}
	w := httptest.NewRecorder()
	l.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/__lab/stats", nil))
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("statistics accepts a write method: %d", w.Code)
	}
}

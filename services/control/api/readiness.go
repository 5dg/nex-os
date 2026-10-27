package api

import (
	"context"
	"errors"
	"time"
)

// dependenciesReady bounds each independent probe. Receiver probes prove their
// body-scope credentials without requesting an execution grant or effect.
func (s *Server) dependenciesReady(ctx context.Context) error {
	type dependency struct {
		check func(context.Context) error
		limit time.Duration
	}
	checks := []dependency{{s.DB.Ping, 3 * time.Second}, {s.Policy.Health, 3 * time.Second}, {s.evidenceReady, 3 * time.Second}}
	if s.qualification() {
		checks = append(checks,
			dependency{func(ctx context.Context) error { return s.ModelRPC.Readiness(ctx, string(s.profile())) }, 8 * time.Second},
			dependency{func(ctx context.Context) error { return s.ToolRPC.Readiness(ctx, string(s.profile())) }, 8 * time.Second})
	}
	results := make(chan error, len(checks))
	for _, check := range checks {
		go func(item dependency) {
			probe, stop := context.WithTimeout(ctx, item.limit)
			defer stop()
			results <- item.check(probe)
		}(check)
	}
	for range checks {
		select {
		case e := <-results:
			if e != nil {
				return errors.New("required dependency readiness failed")
			}
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}

//go:build integration

package api

import (
	"context"
	"crypto/rand"
	"os"
	"strings"
	"testing"

	"github.com/5dg/nex-os/packages/broker"
	"github.com/5dg/nex-os/services/control/devseed"
	"github.com/5dg/nex-os/services/control/migrations"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Disposable schemas prove seeding cannot relabel previously edited content as
// admitted synthetic data. No runtime jobs, manifests or completions are forged.
func TestQualificationSeedPreservesEditedSources(t *testing.T) {
	ctx := context.Background()
	raw := os.Getenv("NEX_TEST_DATABASE_URL")
	if raw == "" {
		t.Fatal("NEX_TEST_DATABASE_URL required for isolated disposable schemas")
	}
	admin, e := pgxpool.New(ctx, raw)
	if e != nil {
		t.Fatal("test database configuration unavailable")
	}
	defer admin.Close()
	for _, tc := range []struct {
		name, sql string
		args      []any
	}{{name: "fresh"}, {name: "edited bytes with updated digest", sql: `UPDATE document_bodies SET content=$1,content_digest=$2 WHERE resource_id='review-bob'`, args: []any{"unadmitted replacement synthetic bytes", broker.Hash([]byte("unadmitted replacement synthetic bytes"))}}, {name: "digest only", sql: `UPDATE document_bodies SET content_digest=$1 WHERE resource_id='review-bob'`, args: []any{broker.Hash([]byte("wrong digest"))}}, {name: "classification", sql: `UPDATE resources SET classification='internal' WHERE id='review-bob'`}, {name: "version", sql: `UPDATE resources SET version='v2' WHERE id='review-bob'`}, {name: "kind", sql: `UPDATE resources SET kind='model' WHERE id='review-bob'`}} {
		t.Run(tc.name, func(t *testing.T) {
			schema := "qual_seed_" + strings.ToLower(rand.Text())
			if _, e := admin.Exec(ctx, "CREATE SCHEMA "+schema); e != nil {
				t.Fatal("disposable schema create failed")
			}
			defer admin.Exec(ctx, "DROP SCHEMA "+schema+" CASCADE")
			config, e := pgxpool.ParseConfig(raw)
			if e != nil {
				t.Fatal("test database config invalid")
			}
			config.ConnConfig.RuntimeParams["search_path"] = schema
			db, e := pgxpool.NewWithConfig(ctx, config)
			if e != nil {
				t.Fatal("disposable schema pool failed")
			}
			defer db.Close()
			if e = migrations.Apply(ctx, db); e != nil {
				t.Fatal(e)
			}
			if e = devseed.Seed(ctx, db, "https://issuer.nex.test:9444"); e != nil {
				t.Fatal(e)
			}
			if e = devseed.SeedWorkflow(ctx, db, "https://issuer.nex.test:9444"); e != nil {
				t.Fatal(e)
			}
			if tc.sql != "" {
				if _, e = db.Exec(ctx, tc.sql, tc.args...); e != nil {
					t.Fatal(e)
				}
			}
			var before, after string
			const snapshot = `SELECT jsonb_build_object('body',b.content,'digest',b.content_digest,'version',r.version,'class',r.classification,'kind',r.kind)::text FROM document_bodies b JOIN resources r ON r.tenant_id=b.tenant_id AND r.id=b.resource_id WHERE b.resource_id='review-bob'`
			if e = db.QueryRow(ctx, snapshot).Scan(&before); e != nil {
				t.Fatal(e)
			}
			err := devseed.SeedQualificationWorkflow(ctx, db, "https://issuer.nex.test:9444")
			if (err != nil) != (tc.sql != "") {
				t.Fatal("qualification admission did not distinguish exact fixture from edited source")
			}
			if e = db.QueryRow(ctx, snapshot).Scan(&after); e != nil {
				t.Fatal(e)
			}
			if before != after {
				t.Fatal("qualification seed modified existing source")
			}
			var admissions int
			if e = db.QueryRow(ctx, `SELECT count(*) FROM document_admissions`).Scan(&admissions); e != nil {
				t.Fatal(e)
			}
			want := 2
			if tc.sql != "" {
				want = 0
			}
			if admissions != want {
				t.Fatalf("admission count %d want %d; transaction must roll back earlier Alice admission on edited Bob source", admissions, want)
			}
		})
	}
}

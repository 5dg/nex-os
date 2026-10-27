package devseed

import (
	"context"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Seed is called only by an explicitly development-only command, never API startup.
func Seed(ctx context.Context, db *pgxpool.Pool, issuer string) error {
	tx, err := db.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	for _, q := range []string{
		`INSERT INTO tenants(id,name) VALUES('tenant-a','Synthetic contractor A'),('tenant-b','Synthetic contractor B') ON CONFLICT DO NOTHING`,
	} {
		if _, err = tx.Exec(ctx, q); err != nil {
			return err
		}
	}
	for _, u := range []struct{ id, tenant string }{{"alice", "tenant-a"}, {"bob", "tenant-b"}} {
		if _, err = tx.Exec(ctx, `INSERT INTO users(id,tenant_id,issuer,subject,permissions) VALUES($1,$2,$3,$1,ARRAY['document.read','document.export','model.invoke']) ON CONFLICT DO NOTHING`, u.id, u.tenant, issuer); err != nil {
			return err
		}
		if _, err = tx.Exec(ctx, `INSERT INTO delegations(id,tenant_id,user_id,permissions,expires_at) VALUES($1,$2,$3,ARRAY['document.read','document.export','model.invoke'],now()+interval '1 year') ON CONFLICT DO NOTHING`, "delegation-"+u.id, u.tenant, u.id); err != nil {
			return err
		}
		for _, r := range []struct{ id, kind, class string }{{"document-" + u.id, "document", "internal"}, {"restricted-" + u.id, "document", "restricted"}, {"dev-model", "model", "public"}} {
			if _, err = tx.Exec(ctx, `INSERT INTO resources(id,tenant_id,kind,classification,version,reader_ids) VALUES($1,$2,$3,$4,'v1',ARRAY[$5]) ON CONFLICT DO NOTHING`, r.id, u.tenant, r.kind, r.class, u.id); err != nil {
				return err
			}
		}
	}
	return tx.Commit(ctx)
}

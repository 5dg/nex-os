package devseed

import (
	"context"
	"github.com/5dg/nex-os/packages/broker"
	"github.com/jackc/pgx/v5/pgxpool"
)

// SeedWorkflow ingests a bounded, public synthetic fixture set for local testing.
// It never updates existing customer or previously edited records.
func SeedWorkflow(ctx context.Context, db *pgxpool.Pool, issuer string) error {
	tx, e := db.Begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback(ctx)
	for _, x := range []struct{ owner, approver, tenant string }{{"alice", "carol", "tenant-a"}, {"bob", "dave", "tenant-b"}} {
		if _, e = tx.Exec(ctx, `INSERT INTO users(id,tenant_id,issuer,subject,permissions) VALUES($1,$2,$3,$1,ARRAY['document.read','approval.decide']) ON CONFLICT DO NOTHING`, x.approver, x.tenant, issuer); e != nil {
			return e
		}
		if _, e = tx.Exec(ctx, `INSERT INTO resources(id,tenant_id,kind,classification,version,reader_ids) VALUES($1,$2,'document','confidential','v1',ARRAY[$3,$4]) ON CONFLICT DO NOTHING`, "review-"+x.owner, x.tenant, x.owner, x.approver); e != nil {
			return e
		}
		content := "SYNTHETIC TRAINING RECORD — NOT CUI. Contractor " + x.tenant + " requires quarterly access reviews. Evidence exports require an independent approver. No actual customer records are present."
		if _, e = tx.Exec(ctx, `INSERT INTO document_bodies(tenant_id,resource_id,content,content_digest) VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING`, x.tenant, "review-"+x.owner, content, broker.Hash([]byte(content))); e != nil {
			return e
		}
		if _, e = tx.Exec(ctx, `INSERT INTO model_routes(tenant_id,id,approved_classifications) VALUES($1,'dev-model',ARRAY['public','internal','confidential']) ON CONFLICT DO NOTHING`, x.tenant); e != nil {
			return e
		}
		if _, e = tx.Exec(ctx, `INSERT INTO export_destinations(tenant_id,id) VALUES($1,'local-evidence') ON CONFLICT DO NOTHING`, x.tenant); e != nil {
			return e
		}
	}
	return tx.Commit(ctx)
}

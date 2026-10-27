-- Qualification is a distinct authority version. Existing v2 history is retained.
ALTER TABLE execution_manifests DROP CONSTRAINT execution_manifests_version_check;
ALTER TABLE execution_manifests ADD CONSTRAINT execution_manifests_version_check CHECK(version IN (2,3));

CREATE TABLE question_catalogue (
 id text NOT NULL, version text NOT NULL, question text NOT NULL,
 classification text NOT NULL CHECK(classification IN ('public','internal','confidential','restricted')),
 enabled boolean NOT NULL DEFAULT true, lock_version bigint NOT NULL DEFAULT 0, PRIMARY KEY(id,version)
);
INSERT INTO question_catalogue(id,version,question,classification)
 VALUES('access-review-controls','v1','What access review and export controls apply?','internal');
ALTER TABLE jobs ADD COLUMN question_id text;
ALTER TABLE jobs ADD COLUMN question_version text;
ALTER TABLE jobs ADD COLUMN execution_profile text NOT NULL DEFAULT 'development' CHECK(execution_profile IN ('development','synthetic-qualification'));
ALTER TABLE jobs ADD CONSTRAINT job_question_catalogue_fk FOREIGN KEY(question_id,question_version) REFERENCES question_catalogue(id,version);
ALTER TABLE jobs ADD CONSTRAINT qualification_question_required CHECK(execution_profile='development' OR (question_id IS NOT NULL AND question_version IS NOT NULL));

ALTER TABLE model_routes ADD COLUMN provider text NOT NULL DEFAULT 'development';
ALTER TABLE model_routes ADD COLUMN region text NOT NULL DEFAULT 'local';
ALTER TABLE model_routes ADD COLUMN model_id text NOT NULL DEFAULT 'deterministic-review-v1';
ALTER TABLE model_routes ADD COLUMN effective_endpoint text NOT NULL DEFAULT 'local://synthetic-generator';
ALTER TABLE model_routes ADD COLUMN features text[] NOT NULL DEFAULT '{}';
ALTER TABLE model_routes ADD COLUMN template_version text NOT NULL DEFAULT 'review-template-v1';

CREATE TABLE document_admissions (
 tenant_id text NOT NULL, resource_id text NOT NULL, version text NOT NULL,
 content_digest text NOT NULL CHECK(content_digest ~ '^[0-9a-f]{64}$'),
 profile text NOT NULL CHECK(profile='synthetic-qualification'),
 lock_version bigint NOT NULL DEFAULT 0,
 PRIMARY KEY(tenant_id,resource_id,version,profile),
 FOREIGN KEY(tenant_id,resource_id) REFERENCES resources(tenant_id,id)
);
-- Admission rows are inserted by the development administrator only after
-- checking exact predefined fixture bytes. No existing body is auto-admitted.

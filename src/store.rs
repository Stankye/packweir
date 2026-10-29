use crate::model::{Artifact, Decision, Evidence};
use anyhow::{Result, ensure};
use serde::Serialize;
use sqlx::{PgPool, Row, postgres::PgPoolOptions};
use uuid::Uuid;

#[derive(Clone)]
pub struct Store {
    pub pool: PgPool,
}
#[derive(Debug)]
pub struct Job {
    pub id: Uuid,
    pub subject: String,
    pub configuration: String,
    pub filename: String,
    pub lease: Uuid,
    pub context_revision: i64,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct JobStatus {
    pub state: String,
    pub attempts: i32,
    pub lease_until: Option<chrono::DateTime<chrono::Utc>>,
    pub error: Option<String>,
}

impl Store {
    pub async fn connect(url: &str) -> Result<Self> {
        let pool = PgPoolOptions::new()
            .max_connections(10)
            .connect(url)
            .await?;
        sqlx::migrate!().run(&pool).await?;
        Ok(Self { pool })
    }
    pub async fn register(&self, artifact: &Artifact) -> Result<Artifact> {
        let mut artifact = artifact.clone();
        let mut tx = self.pool.begin().await?;
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
            .bind(serde_json::to_string(&(
                &artifact.repository,
                &artifact.origin,
            ))?)
            .execute(&mut *tx)
            .await?;
        let claims: Vec<Option<serde_json::Value>> = sqlx::query_scalar(
            "SELECT package FROM package_claims WHERE repository=$1 AND origin=$2 LIMIT 2",
        )
        .bind(&artifact.repository)
        .bind(&artifact.origin)
        .fetch_all(&mut *tx)
        .await?;
        if !claims.is_empty() {
            artifact.package = if claims.len() == 1 {
                claims[0].clone().map(serde_json::from_value).transpose()?
            } else {
                None
            };
        }
        let previous = sqlx::query(
            "SELECT digest,filename,package FROM artifacts WHERE repository=$1 AND origin=$2 FOR UPDATE",
        )
        .bind(&artifact.repository)
        .bind(&artifact.origin)
        .fetch_optional(&mut *tx)
        .await?;
        let package = artifact
            .package
            .as_ref()
            .map(serde_json::to_value)
            .transpose()?;
        sqlx::query("INSERT INTO artifacts(repository,origin,digest,size,filename,content_type,package) VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(repository,origin) DO UPDATE SET digest=EXCLUDED.digest,size=EXCLUDED.size,filename=EXCLUDED.filename,content_type=EXCLUDED.content_type,package=EXCLUDED.package,updated_at=now()")
            .bind(&artifact.repository).bind(&artifact.origin).bind(&artifact.digest).bind(artifact.size).bind(&artifact.filename).bind(&artifact.content_type).bind(&package).execute(&mut *tx).await?;
        sqlx::query("INSERT INTO contexts(subject) VALUES($1) ON CONFLICT DO NOTHING")
            .bind(&artifact.digest)
            .execute(&mut *tx)
            .await?;
        if let Some(previous) = previous {
            let old: String = previous.get("digest");
            if old != artifact.digest
                || previous.get::<String, _>("filename") != artifact.filename
                || previous.get::<Option<serde_json::Value>, _>("package") != package
            {
                let mut subjects = vec![old, artifact.digest.clone()];
                subjects.sort();
                subjects.dedup();
                for subject in subjects {
                    sqlx::query("INSERT INTO contexts(subject,revision) VALUES($1,1) ON CONFLICT(subject) DO UPDATE SET revision=contexts.revision+1")
                        .bind(subject).execute(&mut *tx).await?;
                }
            }
        }
        tx.commit().await?;
        Ok(artifact)
    }
    pub async fn claimed_identity(
        &self,
        repository: &str,
        origin: &str,
    ) -> Result<(bool, Option<crate::identity::PackageIdentity>)> {
        let claims: Vec<Option<serde_json::Value>> = sqlx::query_scalar(
            "SELECT package FROM package_claims WHERE repository=$1 AND origin=$2 LIMIT 2",
        )
        .bind(repository)
        .bind(origin)
        .fetch_all(&self.pool)
        .await?;
        Ok((
            !claims.is_empty(),
            if claims.len() == 1 {
                claims[0].clone().map(serde_json::from_value).transpose()?
            } else {
                None
            },
        ))
    }
    pub async fn observe_claim(
        &self,
        repository: &str,
        claim: &crate::identity::IdentityClaim,
    ) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
            .bind(serde_json::to_string(&(repository, &claim.origin))?)
            .execute(&mut *tx)
            .await?;
        let coordinate = claim
            .package
            .as_ref()
            .map(|p| p.purl.as_str())
            .unwrap_or("unidentified");
        let package = claim
            .package
            .as_ref()
            .map(serde_json::to_value)
            .transpose()?;
        let inserted=sqlx::query("INSERT INTO package_claims(repository,origin,coordinate,source,package) VALUES($1,$2,$3,$4,$5) ON CONFLICT DO NOTHING")
            .bind(repository).bind(&claim.origin).bind(coordinate).bind(&claim.source).bind(package).execute(&mut *tx).await?.rows_affected();
        if inserted > 0 {
            let claims: Vec<Option<serde_json::Value>> = sqlx::query_scalar(
                "SELECT package FROM package_claims WHERE repository=$1 AND origin=$2 LIMIT 2",
            )
            .bind(repository)
            .bind(&claim.origin)
            .fetch_all(&mut *tx)
            .await?;
            let package = if claims.len() == 1 {
                claims[0].clone()
            } else {
                None
            };
            let affected:Option<String>=sqlx::query_scalar("UPDATE artifacts SET package=$3,updated_at=now() WHERE repository=$1 AND origin=$2 AND package IS DISTINCT FROM $3 RETURNING digest")
                .bind(repository).bind(&claim.origin).bind(package).fetch_optional(&mut *tx).await?;
            if let Some(subject) = affected {
                sqlx::query("INSERT INTO contexts(subject,revision) VALUES($1,1) ON CONFLICT(subject) DO UPDATE SET revision=contexts.revision+1")
                    .bind(subject).execute(&mut *tx).await?;
            }
        }
        tx.commit().await?;
        Ok(())
    }
    pub async fn artifact(&self, repository: &str, origin: &str) -> Result<Option<Artifact>> {
        let row = sqlx::query("SELECT * FROM artifacts WHERE repository=$1 AND origin=$2")
            .bind(repository)
            .bind(origin)
            .fetch_optional(&self.pool)
            .await?;
        row.map(|r| {
            Ok(Artifact {
                repository: r.get("repository"),
                origin: r.get("origin"),
                digest: r.get("digest"),
                size: r.get("size"),
                filename: r.get("filename"),
                content_type: r.get("content_type"),
                package: r
                    .get::<Option<serde_json::Value>, _>("package")
                    .map(serde_json::from_value)
                    .transpose()?,
            })
        })
        .transpose()
    }
    pub async fn artifacts(&self, subject: &str) -> Result<Vec<Artifact>> {
        let rows = sqlx::query(
            "SELECT * FROM artifacts WHERE digest=$1 ORDER BY repository,origin LIMIT 257",
        )
        .bind(subject)
        .fetch_all(&self.pool)
        .await?;
        ensure!(
            rows.len() <= 256,
            "too many delivery contexts for inspection"
        );
        rows.into_iter()
            .map(|r| {
                Ok(Artifact {
                    repository: r.get("repository"),
                    origin: r.get("origin"),
                    digest: r.get("digest"),
                    size: r.get("size"),
                    filename: r.get("filename"),
                    content_type: r.get("content_type"),
                    package: r
                        .get::<Option<serde_json::Value>, _>("package")
                        .map(serde_json::from_value)
                        .transpose()?,
                })
            })
            .collect()
    }
    pub async fn evidence_history(
        &self,
        subject: &str,
        configuration: &str,
    ) -> Result<Vec<Evidence>> {
        // Keep the latest applicable outcome and latest expired/future outcome per check.
        // This preserves hard failures and avoids losing a valid older check to repeated scans.
        let rows = sqlx::query("SELECT DISTINCT ON(check_name,(created_at<=now() AND expires_at>now()),document->>'outcome') document FROM evidence WHERE subject=$1 AND configuration=$2 AND context_revision=COALESCE((SELECT revision FROM contexts WHERE subject=$1),0) ORDER BY check_name,(created_at<=now() AND expires_at>now()),document->>'outcome',created_at DESC")
            .bind(subject).bind(configuration).fetch_all(&self.pool).await?;
        rows.iter()
            .map(|r| Ok(serde_json::from_value(r.get("document"))?))
            .collect()
    }
    pub async fn enqueue_delivery(
        &self,
        artifact: &Artifact,
        configuration: &str,
        engine: &str,
    ) -> Result<()> {
        sqlx::query("INSERT INTO contexts(subject) VALUES($1) ON CONFLICT DO NOTHING")
            .bind(&artifact.digest)
            .execute(&self.pool)
            .await?;
        sqlx::query("INSERT INTO jobs(id,subject,configuration,filename,context_revision,engine_configuration,scope) VALUES($1,$2,$3,$4,(SELECT revision FROM contexts WHERE subject=$2),$5,$6) ON CONFLICT(subject,configuration) DO UPDATE SET state=CASE WHEN jobs.state IN ('complete','failed') OR jobs.context_revision<>EXCLUDED.context_revision THEN 'queued' ELSE jobs.state END,attempts=CASE WHEN jobs.state IN ('complete','failed') OR jobs.context_revision<>EXCLUDED.context_revision THEN 0 ELSE jobs.attempts END,context_revision=EXCLUDED.context_revision")
            .bind(Uuid::new_v4()).bind(&artifact.digest).bind(configuration).bind(&artifact.filename).bind(engine).bind(serde_json::to_value(artifact.scope())?).execute(&self.pool).await?;
        Ok(())
    }
    pub async fn job_scope(&self, id: Uuid) -> Result<Option<crate::identity::DeliveryScope>> {
        let scope: Option<serde_json::Value> =
            sqlx::query_scalar("SELECT scope FROM jobs WHERE id=$1")
                .bind(id)
                .fetch_one(&self.pool)
                .await?;
        scope
            .map(serde_json::from_value)
            .transpose()
            .map_err(Into::into)
    }
    pub async fn job_status(
        &self,
        subject: &str,
        configuration: &str,
    ) -> Result<Option<JobStatus>> {
        let row = sqlx::query("SELECT state,attempts,lease_until,error FROM jobs WHERE subject=$1 AND configuration=$2 AND context_revision=COALESCE((SELECT revision FROM contexts WHERE subject=$1),0)")
            .bind(subject).bind(configuration).fetch_optional(&self.pool).await?;
        Ok(row.map(|r| JobStatus {
            state: r.get("state"),
            attempts: r.get("attempts"),
            lease_until: r.get("lease_until"),
            error: r.get("error"),
        }))
    }
    pub async fn evidence(&self, subject: &str, configuration: &str) -> Result<Vec<Evidence>> {
        let rows = sqlx::query("SELECT document FROM evidence WHERE subject=$1 AND configuration=$2 AND context_revision=COALESCE((SELECT revision FROM contexts WHERE subject=$1),0) AND expires_at > now() ORDER BY created_at")
            .bind(subject).bind(configuration).fetch_all(&self.pool).await?;
        rows.iter()
            .map(|r| Ok(serde_json::from_value(r.get("document"))?))
            .collect()
    }
    pub async fn enqueue(&self, subject: &str, configuration: &str, filename: &str) -> Result<()> {
        sqlx::query("INSERT INTO contexts(subject) VALUES($1) ON CONFLICT DO NOTHING")
            .bind(subject)
            .execute(&self.pool)
            .await?;
        sqlx::query("INSERT INTO jobs(id,subject,configuration,filename,context_revision) VALUES($1,$2,$3,$4,(SELECT revision FROM contexts WHERE subject=$2)) ON CONFLICT(subject,configuration) DO UPDATE SET state=CASE WHEN jobs.state IN ('complete','failed') OR jobs.context_revision<>EXCLUDED.context_revision THEN 'queued' ELSE jobs.state END, attempts=CASE WHEN jobs.state IN ('complete','failed') OR jobs.context_revision<>EXCLUDED.context_revision THEN 0 ELSE jobs.attempts END,context_revision=EXCLUDED.context_revision")
            .bind(Uuid::new_v4()).bind(subject).bind(configuration).bind(filename).execute(&self.pool).await?;
        Ok(())
    }
    pub async fn lease(&self, configuration: &str, seconds: i32) -> Result<Option<Job>> {
        ensure!(seconds > 0, "lease duration must be positive");
        sqlx::query("UPDATE jobs SET state='failed',error='lease expired after maximum attempts',lease_until=NULL WHERE (configuration=$1 OR engine_configuration=$1) AND state='running' AND lease_until<now() AND attempts>=3")
            .bind(configuration).execute(&self.pool).await?;
        let lease = Uuid::new_v4();
        let row = sqlx::query("UPDATE jobs SET state='running', lease_token=$2, lease_until=now()+make_interval(secs => $3), attempts=attempts+1 WHERE id=(SELECT id FROM jobs WHERE (configuration=$1 OR engine_configuration=$1) AND attempts<3 AND (state='queued' OR (state='running' AND lease_until<now())) ORDER BY created_at FOR UPDATE SKIP LOCKED LIMIT 1) RETURNING id,subject,configuration,filename,context_revision")
            .bind(configuration).bind(lease).bind(seconds as f64).fetch_optional(&self.pool).await?;
        Ok(row.map(|r| Job {
            id: r.get("id"),
            subject: r.get("subject"),
            configuration: r.get("configuration"),
            filename: r.get("filename"),
            lease,
            context_revision: r.get("context_revision"),
        }))
    }
    pub async fn invalidate(&self, subject: &str) -> Result<()> {
        // A new context revision also prevents an already-running worker from committing old results.
        sqlx::query("INSERT INTO contexts(subject,revision) VALUES($1,1) ON CONFLICT(subject) DO UPDATE SET revision=contexts.revision+1")
            .bind(subject).execute(&self.pool).await?;
        Ok(())
    }
    pub async fn complete(&self, job: &Job, evidence: &[Evidence]) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        let current: i64 =
            sqlx::query_scalar("SELECT revision FROM contexts WHERE subject=$1 FOR UPDATE")
                .bind(&job.subject)
                .fetch_one(&mut *tx)
                .await?;
        ensure!(
            current == job.context_revision,
            "evidence context changed during analysis"
        );
        let locked = sqlx::query("SELECT id FROM jobs WHERE id=$1 AND lease_token=$2 AND state='running' AND lease_until>now() FOR UPDATE")
            .bind(job.id).bind(job.lease).fetch_optional(&mut *tx).await?;
        ensure!(locked.is_some(), "job lease lost");
        for e in evidence {
            ensure!(
                e.subject == job.subject && e.configuration == job.configuration,
                "evidence binding mismatch"
            );
            sqlx::query("INSERT INTO evidence(id,subject,check_name,configuration,created_at,expires_at,document,context_revision) VALUES($1,$2,$3,$4,$5,$6,$7,$8)")
                .bind(Uuid::new_v4()).bind(&e.subject).bind(&e.check).bind(&e.configuration).bind(e.created_at).bind(e.expires_at).bind(serde_json::to_value(e)?).bind(job.context_revision).execute(&mut *tx).await?;
        }
        sqlx::query("UPDATE jobs SET state='complete',lease_until=NULL WHERE id=$1")
            .bind(job.id)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(())
    }
    pub async fn fail(&self, job: &Job) -> Result<()> {
        sqlx::query("UPDATE jobs SET state=CASE WHEN attempts>=3 THEN 'failed' ELSE 'queued' END,error='worker failed',lease_until=NULL WHERE id=$1 AND lease_token=$2 AND state='running'")
            .bind(job.id).bind(job.lease).execute(&self.pool).await?;
        Ok(())
    }
    pub async fn decision(
        &self,
        repo: &str,
        subject: &str,
        config: &str,
        decision: &Decision,
    ) -> Result<()> {
        sqlx::query(
            "INSERT INTO decisions(repository,subject,configuration,document) VALUES($1,$2,$3,$4)",
        )
        .bind(repo)
        .bind(subject)
        .bind(config)
        .bind(serde_json::to_value(decision)?)
        .execute(&self.pool)
        .await?;
        Ok(())
    }
    pub async fn delivery_decision(
        &self,
        artifact: &Artifact,
        configuration: &str,
        policy: &crate::policy::EffectivePolicy,
        decision: &Decision,
    ) -> Result<()> {
        let mut document = serde_json::to_value(decision)?;
        document["scope"] = serde_json::to_value(artifact.scope())?;
        document["policy"] = serde_json::to_value(policy)?;
        sqlx::query(
            "INSERT INTO decisions(repository,subject,configuration,document) VALUES($1,$2,$3,$4)",
        )
        .bind(&artifact.repository)
        .bind(&artifact.digest)
        .bind(configuration)
        .bind(document)
        .execute(&self.pool)
        .await?;
        Ok(())
    }
    pub async fn audit(&self, action: &str, subject: &str, details: impl Serialize) -> Result<()> {
        sqlx::query("INSERT INTO audit(action,subject,details) VALUES($1,$2,$3)")
            .bind(action)
            .bind(subject)
            .bind(serde_json::to_value(details)?)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
    pub async fn document(
        &self,
        subject: &str,
        kind: &str,
        origin: &str,
        digest: &str,
    ) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        let inserted=sqlx::query("INSERT INTO documents(id,subject,kind,origin,blob_digest) VALUES($1,$2,$3,$4,$5) ON CONFLICT DO NOTHING")
            .bind(Uuid::new_v4()).bind(subject).bind(kind).bind(origin).bind(digest).execute(&mut *tx).await?.rows_affected();
        if inserted > 0 && origin != "artifact_observed" {
            sqlx::query("INSERT INTO contexts(subject,revision) VALUES($1,1) ON CONFLICT(subject) DO UPDATE SET revision=contexts.revision+1")
                .bind(subject).execute(&mut *tx).await?;
        }
        tx.commit().await?;
        Ok(())
    }
    pub async fn documents(&self, subject: &str) -> Result<Vec<serde_json::Value>> {
        let rows = sqlx::query(
            "SELECT id,kind,origin,blob_digest FROM documents WHERE subject=$1 ORDER BY created_at",
        )
        .bind(subject)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.iter().map(|r| serde_json::json!({"id":r.get::<Uuid,_>("id"),"kind":r.get::<String,_>("kind"),"origin":r.get::<String,_>("origin"),"blob_digest":r.get::<String,_>("blob_digest")})).collect())
    }
    pub async fn identities(&self, subject: &str) -> Result<Vec<serde_json::Value>> {
        self.artifacts(subject)
            .await?
            .iter()
            .map(|a| Ok(serde_json::to_value(a.scope())?))
            .collect()
    }
}

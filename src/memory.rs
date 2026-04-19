#![cfg_attr(not(test), allow(dead_code))]

use anyhow::{Context, Result};
use chrono::Utc;
use rusqlite::{params, Connection};
use sha2::{Digest, Sha256};
use std::path::Path;

pub struct MemoryStore {
    conn: Connection,
}

impl MemoryStore {
    pub fn open(cwd: &Path) -> Result<Self> {
        let db_path = cwd.join(".kiro").join("cortex-memory.db");
        if let Some(p) = db_path.parent() { std::fs::create_dir_all(p)?; }
        let conn = Connection::open(&db_path).context("Failed to open memory DB")?;
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000;")?;
        let store = Self { conn };
        store.migrate()?;
        Ok(store)
    }

    pub fn open_path(db_path: &Path) -> Result<Self> {
        if let Some(p) = db_path.parent() { std::fs::create_dir_all(p)?; }
        let conn = Connection::open(db_path)?;
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000;")?;
        let store = Self { conn };
        store.migrate()?;
        Ok(store)
    }

    fn migrate(&self) -> Result<()> {
        self.conn.execute_batch("
            CREATE TABLE IF NOT EXISTS memory_chunks (
                id TEXT PRIMARY KEY,
                session_id TEXT NOT NULL,
                hook_type TEXT NOT NULL,
                tool_name TEXT,
                content TEXT NOT NULL,
                content_hash TEXT NOT NULL,
                metadata TEXT,
                importance REAL DEFAULT 0.5,
                created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_chunks_session ON memory_chunks(session_id);
            CREATE INDEX IF NOT EXISTS idx_chunks_hash ON memory_chunks(content_hash);
            CREATE INDEX IF NOT EXISTS idx_chunks_created ON memory_chunks(created_at);

            CREATE TABLE IF NOT EXISTS sessions (
                id TEXT PRIMARY KEY,
                project_path TEXT NOT NULL,
                started_at TEXT NOT NULL,
                ended_at TEXT,
                status TEXT DEFAULT 'active',
                chunk_count INTEGER DEFAULT 0,
                summary TEXT,
                guard_stats TEXT
            );

            CREATE TABLE IF NOT EXISTS entities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                entity_type TEXT NOT NULL,
                properties TEXT,
                created_at TEXT NOT NULL
            );
            CREATE UNIQUE INDEX IF NOT EXISTS idx_entity_name_type ON entities(name, entity_type);

            CREATE TABLE IF NOT EXISTS triples (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                subject_id INTEGER REFERENCES entities(id),
                predicate TEXT NOT NULL,
                object_id INTEGER REFERENCES entities(id),
                valid_from TEXT NOT NULL,
                valid_to TEXT,
                confidence REAL DEFAULT 1.0,
                source_chunk_id TEXT,
                created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_triples_subject ON triples(subject_id);
            CREATE INDEX IF NOT EXISTS idx_triples_valid ON triples(valid_from, valid_to);

            CREATE VIRTUAL TABLE IF NOT EXISTS chunks_fts USING fts5(content, content='memory_chunks', content_rowid='rowid');

            CREATE TABLE IF NOT EXISTS memory_vectors (
                chunk_id TEXT PRIMARY KEY REFERENCES memory_chunks(id),
                embedding BLOB NOT NULL,
                model_version TEXT NOT NULL
            );
        ")?;
        Ok(())
    }

    // --- Chunk storage ---

    pub fn store_chunk(&self, session_id: &str, hook_type: &str, tool_name: Option<&str>, content: &str, metadata: Option<&str>) -> Result<Option<String>> {
        let hash = content_hash(content);
        // Dedup: skip if same hash within 30s
        let exists: bool = self.conn.query_row(
            "SELECT COUNT(*) > 0 FROM memory_chunks WHERE content_hash = ?1 AND created_at > datetime('now', '-30 seconds')",
            params![hash], |r| r.get(0)
        ).unwrap_or(false);
        if exists { return Ok(None); }

        let now = Utc::now().to_rfc3339();
        let id = format!("{}_{}", &session_id[..8.min(session_id.len())], &content_hash(&format!("{}{}", hash, now)));
        let inserted = self.conn.execute(
            "INSERT INTO memory_chunks (id, session_id, hook_type, tool_name, content, content_hash, metadata, created_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
            params![id, session_id, hook_type, tool_name, content, hash, metadata, now],
        )?;
        if inserted == 0 { return Ok(None); }
        // Update FTS
        let _ = self.conn.execute("INSERT INTO chunks_fts(rowid, content) SELECT rowid, content FROM memory_chunks WHERE id = ?1", params![id]);
        // Update session chunk count
        self.conn.execute("UPDATE sessions SET chunk_count = chunk_count + 1 WHERE id = ?1", params![session_id])?;
        Ok(Some(id))
    }

    // --- Session lifecycle ---

    pub fn start_session(&self, session_id: &str, project_path: &str) -> Result<()> {
        let now = Utc::now().to_rfc3339();
        self.conn.execute(
            "INSERT OR IGNORE INTO sessions (id, project_path, started_at) VALUES (?1, ?2, ?3)",
            params![session_id, project_path, now],
        )?;
        Ok(())
    }

    pub fn end_session(&self, session_id: &str, summary: Option<&str>, guard_stats: Option<&str>) -> Result<()> {
        let now = Utc::now().to_rfc3339();
        self.conn.execute(
            "UPDATE sessions SET ended_at = ?1, status = 'completed', summary = ?2, guard_stats = ?3 WHERE id = ?4",
            params![now, summary, guard_stats, session_id],
        )?;
        Ok(())
    }

    // --- Search ---

    pub fn search_bm25(&self, query: &str, limit: usize) -> Result<Vec<SearchResult>> {
        // Escape FTS5 special characters by quoting each token
        let escaped = query.split_whitespace()
            .map(|w| format!("\"{}\"", w.replace('"', "\"\"")))
            .collect::<Vec<_>>().join(" ");
        if escaped.is_empty() { return Ok(vec![]); }
        let mut stmt = self.conn.prepare(
            "SELECT mc.id, mc.content, mc.session_id, mc.tool_name, mc.created_at, rank
             FROM chunks_fts cf JOIN memory_chunks mc ON cf.rowid = mc.rowid
             WHERE chunks_fts MATCH ?1 ORDER BY rank LIMIT ?2"
        )?;
        let results = stmt.query_map(params![escaped, limit as i64], |row| {
            Ok(SearchResult {
                chunk_id: row.get(0)?, content: row.get(1)?, session_id: row.get(2)?,
                tool_name: row.get(3)?, created_at: row.get(4)?, score: -row.get::<_, f64>(5)?,
            })
        })?.filter_map(|r| r.ok()).collect();
        Ok(results)
    }

    /// Store embedding vector for a chunk
    #[cfg(feature = "embedding")]
    pub fn store_vector(&self, chunk_id: &str, embedding: &[u8], model_version: &str) -> Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO memory_vectors (chunk_id, embedding, model_version) VALUES (?1, ?2, ?3)",
            params![chunk_id, embedding, model_version],
        )?;
        Ok(())
    }

    /// Hybrid search: BM25 + vector similarity (requires embedding feature)
    #[cfg(feature = "embedding")]
    pub fn search_hybrid(&self, query: &str, query_embedding: &[u8], limit: usize) -> Result<Vec<SearchResult>> {
        // Step 1: BM25 candidates (3x overfetch)
        let bm25_results = self.search_bm25(query, limit * 3)?;

        // Step 2: Score all chunks with vectors
        let mut scored: Vec<(SearchResult, f64)> = Vec::new();
        for r in bm25_results {
            let vec_score = self.get_vector_similarity(&r.chunk_id, query_embedding);
            let bm25_norm = r.score / 10.0; // Normalize BM25 to ~0-1 range
            let hybrid = 0.6 * vec_score as f64 + 0.4 * bm25_norm;
            scored.push((r, hybrid));
        }

        // Step 3: Also search by vector only (catch semantic matches BM25 missed)
        let vec_results = self.search_vector_only(query_embedding, limit * 3)?;
        for r in vec_results {
            if scored.iter().any(|(s, _)| s.chunk_id == r.chunk_id) { continue; }
            let hybrid = 0.6 * r.score; // No BM25 component
            scored.push((r, hybrid));
        }

        // Sort by hybrid score descending
        scored.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        scored.truncate(limit);

        Ok(scored.into_iter().map(|(mut r, s)| { r.score = s; r }).collect())
    }

    #[cfg(feature = "embedding")]
    fn get_vector_similarity(&self, chunk_id: &str, query_embedding: &[u8]) -> f32 {
        self.conn.query_row(
            "SELECT embedding FROM memory_vectors WHERE chunk_id = ?1",
            params![chunk_id],
            |row| {
                let blob: Vec<u8> = row.get(0)?;
                Ok(crate::embedding::cosine_similarity(&blob, query_embedding))
            },
        ).unwrap_or(0.0)
    }

    #[cfg(feature = "embedding")]
    fn search_vector_only(&self, query_embedding: &[u8], limit: usize) -> Result<Vec<SearchResult>> {
        let mut stmt = self.conn.prepare(
            "SELECT mv.chunk_id, mc.content, mc.session_id, mc.tool_name, mc.created_at, mv.embedding
             FROM memory_vectors mv JOIN memory_chunks mc ON mv.chunk_id = mc.id"
        )?;
        let mut results: Vec<(SearchResult, f32)> = stmt.query_map([], |row| {
            let blob: Vec<u8> = row.get(5)?;
            let sim = crate::embedding::cosine_similarity(&blob, query_embedding);
            Ok((SearchResult {
                chunk_id: row.get(0)?, content: row.get(1)?, session_id: row.get(2)?,
                tool_name: row.get(3)?, created_at: row.get(4)?, score: sim as f64,
            }, sim))
        })?.filter_map(|r| r.ok()).collect();

        results.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        results.truncate(limit);
        Ok(results.into_iter().map(|(r, _)| r).collect())
    }

    pub fn get_top_chunks(&self, limit: usize) -> Result<Vec<SearchResult>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, content, session_id, tool_name, created_at, importance FROM memory_chunks ORDER BY importance DESC, created_at DESC LIMIT ?1"
        )?;
        let results = stmt.query_map(params![limit as i64], |row| {
            Ok(SearchResult {
                chunk_id: row.get(0)?, content: row.get(1)?, session_id: row.get(2)?,
                tool_name: row.get(3)?, created_at: row.get(4)?, score: row.get(5)?,
            })
        })?.filter_map(|r| r.ok()).collect();
        Ok(results)
    }

    #[cfg_attr(test, allow(dead_code))]
    pub fn get_recent_chunks(&self, limit: usize) -> Result<Vec<SearchResult>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, content, session_id, tool_name, created_at, importance FROM memory_chunks ORDER BY created_at DESC LIMIT ?1"
        )?;
        let results = stmt.query_map(params![limit as i64], |row| {
            Ok(SearchResult {
                chunk_id: row.get(0)?, content: row.get(1)?, session_id: row.get(2)?,
                tool_name: row.get(3)?, created_at: row.get(4)?, score: row.get(5)?,
            })
        })?.filter_map(|r| r.ok()).collect();
        Ok(results)
    }

    // --- Stats ---

    #[cfg_attr(test, allow(dead_code))]
    pub fn get_all_chunks_for_reindex(&self) -> Result<Vec<(String, String)>> {
        let mut stmt = self.conn.prepare("SELECT id, content FROM memory_chunks")?;
        let results = stmt.query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?.filter_map(|r| r.ok()).collect();
        Ok(results)
    }

    pub fn stats(&self) -> Result<MemoryStats> {
        let chunk_count: i64 = self.conn.query_row("SELECT COUNT(*) FROM memory_chunks", [], |r| r.get(0))?;
        let session_count: i64 = self.conn.query_row("SELECT COUNT(*) FROM sessions", [], |r| r.get(0))?;
        let entity_count: i64 = self.conn.query_row("SELECT COUNT(*) FROM entities", [], |r| r.get(0))?;
        let triple_count: i64 = self.conn.query_row("SELECT COUNT(*) FROM triples", [], |r| r.get(0))?;
        Ok(MemoryStats { chunk_count: chunk_count as usize, session_count: session_count as usize, entity_count: entity_count as usize, triple_count: triple_count as usize })
    }

    // --- Forget ---

    pub fn forget_before(&self, before: &str) -> Result<usize> {
        // Delete vectors first (FK constraint)
        self.conn.execute(
            "DELETE FROM memory_vectors WHERE chunk_id IN (SELECT id FROM memory_chunks WHERE datetime(created_at) < datetime(?1))",
            params![before]
        )?;
        let deleted = self.conn.execute(
            "DELETE FROM memory_chunks WHERE datetime(created_at) < datetime(?1)", params![before]
        )?;
        // Rebuild FTS index after bulk delete
        if deleted > 0 {
            let _ = self.conn.execute_batch("INSERT INTO chunks_fts(chunks_fts) VALUES('rebuild')");
            // Fix session chunk counts
            let _ = self.conn.execute_batch(
                "UPDATE sessions SET chunk_count = (SELECT COUNT(*) FROM memory_chunks WHERE session_id = sessions.id)"
            );
        }
        Ok(deleted)
    }

    pub fn forget_chunk(&self, chunk_id: &str) -> Result<bool> {
        let session_id: Option<String> = self.conn.query_row(
            "SELECT session_id FROM memory_chunks WHERE id = ?1", params![chunk_id], |r| r.get(0)
        ).ok();
        // Delete vector first (FK constraint)
        let _ = self.conn.execute("DELETE FROM memory_vectors WHERE chunk_id = ?1", params![chunk_id]);
        let deleted = self.conn.execute("DELETE FROM memory_chunks WHERE id = ?1", params![chunk_id])?;
        if deleted > 0 {
            let _ = self.conn.execute_batch("INSERT INTO chunks_fts(chunks_fts) VALUES('rebuild')");
            if let Some(sid) = session_id {
                let _ = self.conn.execute(
                    "UPDATE sessions SET chunk_count = chunk_count - 1 WHERE id = ?1 AND chunk_count > 0",
                    params![sid]
                );
            }
        }
        Ok(deleted > 0)
    }

    // --- Knowledge Graph ---

    pub fn add_entity(&self, name: &str, entity_type: &str, properties: Option<&str>) -> Result<i64> {
        let now = Utc::now().to_rfc3339();
        self.conn.execute(
            "INSERT OR IGNORE INTO entities (name, entity_type, properties, created_at) VALUES (?1,?2,?3,?4)",
            params![name, entity_type, properties, now],
        )?;
        let id = self.conn.query_row(
            "SELECT id FROM entities WHERE name = ?1 AND entity_type = ?2", params![name, entity_type], |r| r.get(0)
        )?;
        Ok(id)
    }

    pub fn add_triple(&self, subject_id: i64, predicate: &str, object_id: i64, source_chunk: Option<&str>) -> Result<i64> {
        let now = Utc::now().to_rfc3339();
        self.conn.execute(
            "INSERT INTO triples (subject_id, predicate, object_id, valid_from, source_chunk_id, created_at) VALUES (?1,?2,?3,?4,?5,?6)",
            params![subject_id, predicate, object_id, now, source_chunk, now],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    pub fn invalidate_triple(&self, triple_id: i64) -> Result<()> {
        let now = Utc::now().to_rfc3339();
        self.conn.execute("UPDATE triples SET valid_to = ?1 WHERE id = ?2", params![now, triple_id])?;
        Ok(())
    }

    pub fn query_entity_relations(&self, entity_name: &str) -> Result<Vec<Triple>> {
        let mut stmt = self.conn.prepare(
            "SELECT t.id, s.name, t.predicate, o.name, t.valid_from, t.valid_to, t.confidence
             FROM triples t JOIN entities s ON t.subject_id = s.id JOIN entities o ON t.object_id = o.id
             WHERE (s.name = ?1 OR o.name = ?1) AND t.valid_to IS NULL"
        )?;
        let results = stmt.query_map(params![entity_name], |row| {
            Ok(Triple {
                id: row.get(0)?, subject: row.get(1)?, predicate: row.get(2)?, object: row.get(3)?,
                valid_from: row.get(4)?, valid_to: row.get(5)?, confidence: row.get(6)?,
            })
        })?.filter_map(|r| r.ok()).collect();
        Ok(results)
    }
}

#[derive(Debug)]
pub struct SearchResult {
    pub chunk_id: String,
    pub content: String,
    #[cfg_attr(test, allow(dead_code))]
    pub session_id: String,
    #[cfg_attr(test, allow(dead_code))]
    pub tool_name: Option<String>,
    pub created_at: String,
    pub score: f64,
}

#[derive(Debug)]
pub struct MemoryStats {
    pub chunk_count: usize,
    pub session_count: usize,
    pub entity_count: usize,
    pub triple_count: usize,
}

#[derive(Debug)]
pub struct Triple {
    #[cfg_attr(test, allow(dead_code))]
    pub id: i64,
    #[cfg_attr(test, allow(dead_code))]
    pub subject: String,
    pub predicate: String,
    pub object: String,
    #[cfg_attr(test, allow(dead_code))]
    pub valid_from: String,
    #[cfg_attr(test, allow(dead_code))]
    pub valid_to: Option<String>,
    #[cfg_attr(test, allow(dead_code))]
    pub confidence: f64,
}

fn content_hash(content: &str) -> String {
    let mut h = Sha256::new();
    h.update(content.as_bytes());
    let r = h.finalize();
    format!("{:x}", r)[..16].to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn test_store() -> (TempDir, MemoryStore) {
        let dir = TempDir::new().unwrap();
        let store = MemoryStore::open_path(&dir.path().join("test.db")).unwrap();
        (dir, store)
    }

    #[test]
    fn store_and_retrieve_chunk() {
        let (_dir, store) = test_store();
        store.start_session("s1", "/project").unwrap();
        let id = store.store_chunk("s1", "postToolUse", Some("read"), "hello world", None).unwrap();
        assert!(id.is_some());
        let results = store.search_bm25("hello", 10).unwrap();
        assert!(!results.is_empty());
        assert!(results[0].content.contains("hello"));
    }

    #[test]
    fn dedup_within_30s() {
        let (_dir, store) = test_store();
        store.start_session("s1", "/project").unwrap();
        let id1 = store.store_chunk("s1", "postToolUse", None, "same content", None).unwrap();
        let id2 = store.store_chunk("s1", "postToolUse", None, "same content", None).unwrap();
        assert!(id1.is_some());
        assert!(id2.is_none()); // Deduped
    }

    #[test]
    fn session_lifecycle() {
        let (_dir, store) = test_store();
        store.start_session("s1", "/project").unwrap();
        store.store_chunk("s1", "postToolUse", None, "chunk 1", None).unwrap();
        store.store_chunk("s1", "postToolUse", None, "chunk 2 different", None).unwrap();
        store.end_session("s1", Some("Did stuff"), Some(r#"{"blocked":1}"#)).unwrap();
        let stats = store.stats().unwrap();
        assert_eq!(stats.chunk_count, 2);
        assert_eq!(stats.session_count, 1);
    }

    #[test]
    fn search_bm25_works() {
        let (_dir, store) = test_store();
        store.start_session("s1", "/project").unwrap();
        store.store_chunk("s1", "postToolUse", None, "setup docker compose for postgresql", None).unwrap();
        store.store_chunk("s1", "postToolUse", None, "configured redis cache layer", None).unwrap();
        let results = store.search_bm25("docker postgresql", 10).unwrap();
        assert!(!results.is_empty());
        assert!(results[0].content.contains("docker"));
    }

    #[test]
    fn top_chunks_by_importance() {
        let (_dir, store) = test_store();
        store.start_session("s1", "/project").unwrap();
        store.store_chunk("s1", "postToolUse", None, "important thing", None).unwrap();
        let results = store.get_top_chunks(5).unwrap();
        assert!(!results.is_empty());
    }

    #[test]
    fn forget_before_date() {
        let (_dir, store) = test_store();
        store.start_session("s1", "/project").unwrap();
        store.store_chunk("s1", "postToolUse", None, "old data", None).unwrap();
        let deleted = store.forget_before("2099-01-01T00:00:00Z").unwrap();
        assert_eq!(deleted, 1);
        assert_eq!(store.stats().unwrap().chunk_count, 0);
    }

    #[test]
    fn forget_specific_chunk() {
        let (_dir, store) = test_store();
        store.start_session("s1", "/project").unwrap();
        let id = store.store_chunk("s1", "postToolUse", None, "to delete", None).unwrap().unwrap();
        assert!(store.forget_chunk(&id).unwrap());
        assert_eq!(store.stats().unwrap().chunk_count, 0);
    }

    // --- Knowledge Graph ---

    #[test]
    fn kg_add_entity_and_triple() {
        let (_dir, store) = test_store();
        let proj = store.add_entity("my-project", "project", None).unwrap();
        let react = store.add_entity("React 18", "concept", None).unwrap();
        let tid = store.add_triple(proj, "uses", react, None).unwrap();
        assert!(tid > 0);
        let rels = store.query_entity_relations("my-project").unwrap();
        assert_eq!(rels.len(), 1);
        assert_eq!(rels[0].predicate, "uses");
        assert_eq!(rels[0].object, "React 18");
    }

    #[test]
    fn kg_invalidate_triple() {
        let (_dir, store) = test_store();
        let proj = store.add_entity("proj", "project", None).unwrap();
        let r17 = store.add_entity("React 17", "concept", None).unwrap();
        let tid = store.add_triple(proj, "uses", r17, None).unwrap();
        store.invalidate_triple(tid).unwrap();
        // Invalidated triples not returned (valid_to IS NULL filter)
        let rels = store.query_entity_relations("proj").unwrap();
        assert!(rels.is_empty());
    }

    #[test]
    fn kg_temporal_query() {
        let (_dir, store) = test_store();
        let proj = store.add_entity("proj", "project", None).unwrap();
        let r17 = store.add_entity("React 17", "concept", None).unwrap();
        let r18 = store.add_entity("React 18", "concept", None).unwrap();
        let old = store.add_triple(proj, "uses", r17, None).unwrap();
        store.invalidate_triple(old).unwrap();
        store.add_triple(proj, "uses", r18, None).unwrap();
        let rels = store.query_entity_relations("proj").unwrap();
        assert_eq!(rels.len(), 1);
        assert_eq!(rels[0].object, "React 18");
    }

    #[test]
    fn stats_counts() {
        let (_dir, store) = test_store();
        let s = store.stats().unwrap();
        assert_eq!(s.chunk_count, 0);
        assert_eq!(s.entity_count, 0);
        store.add_entity("test", "concept", None).unwrap();
        let s = store.stats().unwrap();
        assert_eq!(s.entity_count, 1);
    }
}

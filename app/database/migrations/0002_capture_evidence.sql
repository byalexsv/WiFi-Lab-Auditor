CREATE TABLE IF NOT EXISTS capture_evidence (
    id INTEGER PRIMARY KEY,
    capture_id TEXT NOT NULL UNIQUE,
    material_status TEXT NOT NULL,
    evidence_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS recovery_coverage (
    id INTEGER PRIMARY KEY,
    fingerprint TEXT NOT NULL UNIQUE,
    candidates_tested INTEGER NOT NULL,
    total_candidates INTEGER NOT NULL,
    result TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS structured_events (
    id INTEGER PRIMARY KEY,
    event_type TEXT NOT NULL,
    event_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);

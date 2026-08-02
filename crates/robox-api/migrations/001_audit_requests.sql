CREATE TABLE IF NOT EXISTS audit_requests (
    id TEXT PRIMARY KEY,
    project_name TEXT NOT NULL,
    website_url TEXT,
    repository_url TEXT NOT NULL,
    chains_json TEXT NOT NULL,
    prior_review TEXT NOT NULL CHECK (prior_review IN ('yes', 'no', 'not_sure')),
    scope TEXT NOT NULL,
    email TEXT NOT NULL,
    telegram TEXT,
    contact_consent INTEGER NOT NULL CHECK (contact_consent = 1),
    status TEXT NOT NULL DEFAULT 'new' CHECK (status IN ('new', 'contacted', 'reviewing', 'closed')),
    created_at TEXT NOT NULL
);

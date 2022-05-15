CREATE TABLE IF NOT EXISTS hosts (
 name TEXT NOT NULL,
 ip TEXT NOT NULL,
 status CHAR NOT NULL,
 badscore TEXT,
 token TEXT NOT NULL,
 last_edit TEXT
);
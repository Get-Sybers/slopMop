PRAGMA journal_mode = OFF;
PRAGMA synchronous = OFF;
PRAGMA temp_store = MEMORY;
PRAGMA foreign_keys = ON;

CREATE TABLE files (
    id        INTEGER PRIMARY KEY,
    path      TEXT    NOT NULL,
    name      TEXT    NOT NULL,
    role      TEXT    NOT NULL,
    size      INTEGER NOT NULL,
    lines     INTEGER NOT NULL,
    sha256    TEXT    NOT NULL,
    note      TEXT    NOT NULL,
    stamped   INTEGER NOT NULL,
    stamptext TEXT    NOT NULL,
    modified  BLOB,
    stamp     BLOB,
    effsec    INTEGER NOT NULL,
    effnsec   INTEGER NOT NULL
);

CREATE TABLE tools (
    file INTEGER NOT NULL REFERENCES files(id),
    seq  INTEGER NOT NULL,
    tool TEXT    NOT NULL
);

CREATE TABLE tactics (
    file   INTEGER NOT NULL REFERENCES files(id),
    seq    INTEGER NOT NULL,
    tactic TEXT    NOT NULL
);

CREATE TABLE transforms (
    file   INTEGER NOT NULL REFERENCES files(id),
    seq    INTEGER NOT NULL,
    method TEXT    NOT NULL
);

CREATE TABLE commands (
    file INTEGER NOT NULL REFERENCES files(id),
    seq  INTEGER NOT NULL,
    tool TEXT    NOT NULL,
    text TEXT    NOT NULL,
    line INTEGER NOT NULL
);

CREATE TABLE activities (
    file     INTEGER NOT NULL REFERENCES files(id),
    seq      INTEGER NOT NULL,
    name     TEXT    NOT NULL,
    lines    INTEGER NOT NULL,
    tactics  TEXT    NOT NULL,
    attack   TEXT    NOT NULL,
    atlas    TEXT    NOT NULL,
    evidence TEXT    NOT NULL
);

CREATE TABLE indicators (
    file   INTEGER NOT NULL REFERENCES files(id),
    seq    INTEGER NOT NULL,
    type   TEXT    NOT NULL,
    value  TEXT    NOT NULL,
    start  INTEGER NOT NULL,
    line   INTEGER NOT NULL,
    dollar INTEGER NOT NULL,
    inpath INTEGER NOT NULL
);

CREATE TABLE intelhits (
    file        INTEGER NOT NULL REFERENCES files(id),
    seq         INTEGER NOT NULL,
    type        TEXT    NOT NULL,
    value       TEXT    NOT NULL,
    attribution TEXT    NOT NULL
);

CREATE TABLE exposures (
    file    INTEGER NOT NULL REFERENCES files(id),
    seq     INTEGER NOT NULL,
    kind    TEXT    NOT NULL,
    value   TEXT    NOT NULL,
    account TEXT    NOT NULL,
    form    TEXT    NOT NULL,
    line    INTEGER NOT NULL,
    open    INTEGER NOT NULL
);

CREATE TABLE writes (
    file INTEGER NOT NULL REFERENCES files(id),
    seq  INTEGER NOT NULL,
    base TEXT    NOT NULL
);

CREATE INDEX indicators_type ON indicators(type);
CREATE INDEX indicators_file ON indicators(file);
CREATE INDEX activities_name ON activities(name);
CREATE INDEX exposures_file  ON exposures(file);

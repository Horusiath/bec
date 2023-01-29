package bec

const SCHEMA string = `
CREATE TABLE IF NOT EXISTS nodes(
    id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
    hash NCHAR(32) NOT NULL UNIQUE,
    author NCHAR(32) NOT NULL,
    content BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS edges(
    parent_id INTEGER NOT NULL,
    child_id INTEGER NOT NULL,
    PRIMARY KEY(parent_id, child_id),
    FOREIGN KEY (parent_id) REFERENCES nodes(id),
    FOREIGN KEY (child_id) REFERENCES nodes(id)
);
CREATE TABLE IF NOT EXISTS heads(
    author NCHAR(32) PRIMARY KEY,
    hash NCHAR(32) NOT NULL
);
`

const QUERY_DEPS string = `
WITH RECURSIVE predecessors(id) AS (
    SELECT id as parent_id FROM nodes WHERE hash IN ('e')
    UNION
    SELECT parent_id
    FROM edges s
    JOIN predecessors p ON s.child_id = p.id
)
SELECT * FROM predecessors;
`

const QUERY_NON_DEPS string = `
WITH RECURSIVE predecessors(id) AS (
    SELECT id as parent_id FROM nodes WHERE hash = 'e'
    UNION
    SELECT parent_id
    FROM edges s
    JOIN predecessors p ON s.child_id = p.id
)
SELECT child_id FROM edges s WHERE child_id NOT IN predecessors;
`

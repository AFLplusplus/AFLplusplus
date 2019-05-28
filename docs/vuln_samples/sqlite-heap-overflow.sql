DROP TABLE IF EXISTS t;CREATE VIRTUAL TABLE t0 USING fts4();insert into t0 select zeroblob(0);SAVEPOINT O;insert into t0
select(0);SAVEPOINT E;insert into t0 SELECT 0 UNION SELECT 0'x'ORDER BY x;

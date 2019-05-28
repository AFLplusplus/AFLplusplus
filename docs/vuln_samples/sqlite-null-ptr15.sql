CREATE VIRTUAL TABLE t4 USING fts4(0,b,c,notindexed=0);INSERT INTO t4 VALUES('','','0');BEGIN;INSERT INTO t4 VALUES('','','0');INSERT INTO t4(t4)VALUES('integrity-check');

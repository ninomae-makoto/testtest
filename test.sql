\pset tuples_only on
\pset format unaligned
\pset fieldsep '\t'
\pset pager off
\set ON_ERROR_STOP on

WITH src AS (
  -- ここに元のSELECTを入れる。例:
  SELECT id1, id2, other
  FROM your_table
  WHERE status = 'ACTIVE'
)
SELECT
  id1,
  id2,
  /* グループ内の各行（id1,id2以外の列）を配列でまとめる */
  json_agg( to_jsonb(src) - 'id1' - 'id2' ORDER BY other ) AS rows_json
FROM src
GROUP BY id1, id2
ORDER BY id1, id2;

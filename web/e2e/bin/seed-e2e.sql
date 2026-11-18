-- Idempotent seed for Playwright findings reproduction e2e (run against disposable DB).

INSERT INTO findings (id, vulnclass, name, severity, summary, evidence, worker, asset_ids, status, reproduction)
VALUES (
  9001,
  'sqli',
  'E2E With Reproduction',
  'high',
  'Playwright seed: structured reproduction',
  'seed evidence',
  'e2e',
  '[]'::jsonb,
  'confirmed',
  '{"entry_point":"GET /e2e/vuln","prerequisites":["已登录"],"steps":[{"request":"GET /e2e/vuln HTTP/1.1\nHost: e2e.local\n\n","response":"HTTP/1.1 200 OK\n\nvulnerable","expected":"200","proves":"漏洞可复现","exchange_id":"e2e-ex-001"}],"provenance":"playwright e2e"}'::jsonb
)
ON CONFLICT (id) DO UPDATE SET
  reproduction = EXCLUDED.reproduction,
  summary = EXCLUDED.summary,
  name = EXCLUDED.name;

INSERT INTO findings (id, vulnclass, name, severity, summary, evidence, worker, asset_ids, status, reproduction)
VALUES (
  9002,
  'info-leak',
  'E2E Without Reproduction',
  'low',
  'Playwright seed: no reproduction column content',
  'seed only',
  'e2e',
  '[]'::jsonb,
  'pending',
  NULL
)
ON CONFLICT (id) DO UPDATE SET reproduction = NULL, summary = EXCLUDED.summary;

SELECT setval(pg_get_serial_sequence('findings', 'id'), GREATEST((SELECT MAX(id) FROM findings), 9002));

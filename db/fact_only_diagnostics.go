package db

// CountFactOnlyTerminalIntents reports completed intents in this exploration
// with a directly yielded fact but no directly yielded finding. It is a
// diagnostic, not a finding or an assertion that any fact indicates a defect.
func (s *ExplorationStore) CountFactOnlyTerminalIntents() (int, error) {
	var count int
	err := s.db.QueryRow(`
SELECT COUNT(*)
FROM exploration_nodes AS i
WHERE i.exploration_id = $1
  AND i.kind = 'intent'
  AND i.state IN ('done', 'blocked', 'exhausted', 'stopped')
  AND EXISTS (
      SELECT 1
      FROM exploration_edges AS e
      JOIN exploration_nodes AS n
        ON n.id = e.dst_id AND n.exploration_id = e.exploration_id
      WHERE e.exploration_id = i.exploration_id
        AND e.src_id = i.id AND e.rel = 'yields' AND n.kind = 'fact'
  )
  AND NOT EXISTS (
      SELECT 1
      FROM exploration_edges AS e
      JOIN exploration_nodes AS n
        ON n.id = e.dst_id AND n.exploration_id = e.exploration_id
      WHERE e.exploration_id = i.exploration_id
        AND e.src_id = i.id AND e.rel = 'yields' AND n.kind = 'finding'
  )`, s.expID).Scan(&count)
	return count, err
}

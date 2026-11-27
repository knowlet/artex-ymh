package db

import "slices"

// ascendingActivityPage consumes a private newest-first result buffer, removing
// the lookahead row and returning the retained page in display order. Callers
// normalize limit before querying and initialize empty results as []Activity{}.
func ascendingActivityPage(desc []Activity, limit int) ([]Activity, bool) {
	hasMore := len(desc) > limit
	if hasMore {
		// Do not retain metadata belonging to rows outside the returned page.
		clear(desc[limit:])
		desc = desc[:limit:limit]
	}
	slices.Reverse(desc)
	return desc, hasMore
}

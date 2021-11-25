#include "ocf/ocf_cache.h"
#include "../src/ocf/ocf_cache_priv.h"
#include "../src/ocf/metadata/metadata_raw.h"
#include "../src/ocf/metadata/metadata_internal.h"

# get collision metadata segment start and size (excluding padding)
void ocf_get_collision_location_helper(ocf_cache_t cache,
		uint64_t *page_start, uint64_t *page_count)
{
	struct ocf_metadata_ctrl *ctrl = cache->metadata.priv;
	struct ocf_metadata_raw *raw = ctrl->raw_desc[metadata_segment_collision];

	*page_start = raw->ssd_pages_offset;
	*page_count = raw->ssd_pages;
}

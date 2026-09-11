# VERTEX UI Improvement Checklist

| # | Improvement | Status |
|---|---|---|
| 1 | Human-readable forensic analysis | ✅ Complete |
| 2 | Center-root 3D correlation graph | ✅ Complete |
| 3 | Dashboard/home overview | ⏳ Pending |
| 4 | Email search/filter by sender/domain/risk/date | ⏳ Pending |
| 5 | Toast notification system | ⏳ Pending |
| 6 | 404 + React error boundary | ⏳ Pending |
| 7 | Command palette / ⌘K | ⏳ Pending |
| 8 | Skeleton loaders | ⏳ Pending |
| 9 | Consistent risk badges + iconography | ⏳ Pending |
| 10 | Sticky/filterable/sortable email table header | ⏳ Pending |
| 11 | Collapsible sidebar | ⏳ Pending |
| 12 | Breadcrumbs on detail pages | ⏳ Pending |
| 13 | Copy-to-clipboard hashes/IDs | ⏳ Pending |
| 14 | Accessible focus states + shared empty states | ⏳ Pending |
| 15 | Subtle route transitions | ⏳ Pending |
| 16 | Comfortable/compact density toggle | ⏳ Pending |

## Item 2 verification
- Backend changes: **None**. The existing graph payload contains nodes and edges sufficient for the requested visualization.
- Root selection: strongest-connected email preferred; falls back to strongest-connected entity.
- Layout: root at center; BFS depth determines visual shells.
- 3D interaction: rotate, pan, zoom, node selection.
- Node details: type, label, identifier, connection count, email navigation.
- Shared infrastructure: preserved from existing `/api/graph/shared` contract.
- Filtering/search: preserved and applied before layout.
- No product feature outside Item 2 added.

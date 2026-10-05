# Retention and Backup

## Data Lifecycle

```
Device Recording ──► Finalized ──► Queued ──► Uploading ──► Acknowledged
                                                                │
                                                         Retained (7-30 days)
                                                                │
                                                            Prunable
                                                                │
                                                Server: Archived (long-term)
```

## Device Retention

### States

| State | Location | Behavior |
|-------|----------|----------|
| `recording` | Active file on microSD | Trip being written with periodic fsync/checkpoints |
| `finalized` | microSD | Immutable bundle; complete and hashable |
| `queued` | microSD | Sealed; awaiting the enrolled phone to pull it over BLE |
| `uploading` | microSD + server staging | Chunked transfer in progress |
| `acknowledged` | microSD + server durable store | Server receipt stored locally |
| `retained` | microSD | Kept for configurable safety window |
| `prunable` | microSD | Eligible for deletion |

### Deletion Rules

1. **Never** delete a trip merely because an HTTP request succeeded
2. Delete **only** after:
   - Server has issued a durable receipt tied to the trip ID and content hash
   - The receipt has been stored locally on the device
   - The configurable retention window has elapsed (default: 14 days)
3. Under storage pressure:
   - Preserve all unsynced trips
   - Prune oldest acknowledged+retained trips first
   - Alert on next home sync if storage was under pressure

### Configurable Parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| `retention_days` | 14 | Days to keep acknowledged trips on device |
| `min_free_mb` | 100 | Minimum free space threshold for alerts |
| `max_spool_gb` | 4 | Maximum total spool size before oldest pruning |
| `prune_batch_size` | 10 | Max trips to prune per cycle |

## Server Retention

### Storage Tiers

| Tier | Content | Retention | Location |
|------|---------|-----------|----------|
| **Raw bundles** | Original immutable device bundles | Indefinite | Object store (filesystem or S3-compatible local) |
| **Normalized data** | PostgreSQL/PostGIS trip records | Indefinite | Database |
| **Derived data** | Decoded records, aggregations | Regenerable; keep current version | Database |
| **Staging** | In-progress uploads | Until acknowledged or expired | Temp directory |

### Raw Bundle Policy

- Raw bundles are **never modified** after receipt
- They serve as the authoritative source of truth
- Server-side operations (compression, normalization) produce new derived records
- Original bundle hash is always preserved for verification

### Database Retention

- Raw GNSS samples: indefinite (primary record)
- Raw IMU summaries: indefinite
- Trip records: indefinite
- Places and tags: indefinite (user-managed)
- Derivation records: keep current version; optionally archive previous
- Staging uploads: auto-expire after 72 hours of inactivity

## Backup Strategy

### What to Back Up

| Component | Method | Frequency |
|-----------|--------|-----------|
| PostgreSQL database | `pg_dump` with PostGIS support | Daily |
| Raw trip bundles (object store) | rsync or rclone to NAS | Daily |
| Server certificates and CA | Manual export to secure offline storage | On change |
| Configuration files | Git-tracked in deploy/ directory | On change |
| Device public keys / enrollment | Included in database backup | Daily |

### Backup Destinations

- **Primary:** Local NAS on same LAN (different failure domain)
- **Optional:** Offsite encrypted backup (only if you consciously accept that destination)
- **Never:** Unencrypted cloud storage

### Restore Procedure

1. Provision a fresh host (see [deploying.md](deploying.md); `deploy/deploy-v3.sh`)
2. Restore PostgreSQL from latest dump
3. Restore raw bundle object store from backup
4. Restore certificates and configuration
5. Verify: browse trips, export data, confirm bundle integrity
6. Re-enroll devices if certificates were rotated

### Restore Validation

| Check | Expected Result |
|-------|----------------|
| Trip count matches | Same number of trips as before backup |
| Bundle hashes match | All raw bundles verify against stored hashes |
| Map view works | Trip routes render correctly on map |
| Export works | GPX/GeoJSON/CSV exports produce valid files |
| Device sync works | Device can resume uploading after restore |

## Data Export

Users can export all data at any time:

| Format | Content |
|--------|---------|
| **Raw bundles** | Original device bundles (zip archive) |
| **GPX** | Trip routes as GPS Exchange Format |
| **GeoJSON** | Trip routes and places as GeoJSON features |
| **CSV** | Tabular trip summaries, samples, events |
| **JSON** | Full trip model with all metadata |

Export includes both raw and derived data. 100% of user data must be exportable.

## Disaster Recovery

### Worst Case: Total Server Loss

1. Trip data on device microSD survives (retention window)
2. Rebuild server from backup
3. Devices re-sync any trips within their retention window
4. Trips beyond device retention window: restored from server backup only

### Worst Case: Device microSD Failure

1. All acknowledged trips are safe on the server
2. Only in-progress recording may be lost
3. Replace microSD, re-provision device
4. Partial data may be salvageable from a failed card with ordinary SD recovery tools. (The former Odin `sd-recover` tool was retired in 2026-10-05.)

### Worst Case: Both Server and Device Loss

1. Restore server from NAS/offsite backup
2. Data between last backup and loss is unrecoverable
3. Regular backup frequency is the primary mitigation

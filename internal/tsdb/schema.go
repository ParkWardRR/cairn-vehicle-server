package tsdb

// Every sample table is keyed on (boot_id, mono_ms), never on wall-clock UTC.
// Ordering truth in a Cairn bundle is (boot_id, seq); UTC is an estimate that
// carries its own uncertainty. mono_ms is the boot-relative clock that the
// device stamped on the frame, so it orders rows within a boot exactly, and
// observed_at rides along as an annotation for anyone who wants to plot against
// a calendar.
//
// Every table also leads with vehicle_id (32 lowercase hex, the manifest's
// binding). boot_id is random per boot and would almost never collide across
// cars, but "almost never" is not a key: every join, window and grouping below
// carries vehicle_id equality as well, so a fuel-trim bin or a boost curve can
// only ever be built from one car's rows.
//
// Column types match the decoder's Go types one to one. The appender is strict
// about that, and it keeps a narrow column narrow: a u8 stays a UTINYINT rather
// than widening to BIGINT and costing memory bandwidth on every scan.
const schemaSQL = `
CREATE TABLE bundles (
    content_root   VARCHAR PRIMARY KEY,
    vehicle_id     VARCHAR NOT NULL,
    bundle_id      VARCHAR,
    device_id      VARCHAR,
    boot_id        VARCHAR,
    origin         VARCHAR,
    decoder_ver    INTEGER,
    output_digest  VARCHAR,
    reproduced     BOOLEAN,
    decode_ms      INTEGER,
    n_position     UINTEGER,
    n_imu          UINTEGER,
    n_obd          UINTEGER,
    n_boost        UINTEGER,
    n_status       UINTEGER,
    n_transition   UINTEGER,
    n_gap          UINTEGER,
    unknown_records INTEGER,
    warnings       VARCHAR,
    -- How the bundle reached the server, from the server's own lifecycle ledger. All four
    -- are NULL for a bundle the ledger has no record of (one read off the SD card, say):
    -- an unknown path is not any of the three.
    path           VARCHAR,       -- ble-relay | wifi-direct | lte
    size_bytes     UBIGINT,       -- bytes stored on commit
    duration_ms    UINTEGER,      -- first offer to commit, a session's pauses included
    received_at    TIMESTAMP      -- when the server committed it
);

CREATE TABLE position (
    vehicle_id VARCHAR NOT NULL,
    content_root VARCHAR, boot_id VARCHAR, mono_ms UINTEGER, seq UINTEGER,
    observed_at  TIMESTAMP,
    lat          DOUBLE, lon DOUBLE,
    alt_m        DOUBLE, speed_mps DOUBLE, heading_deg DOUBLE,
    fix_type     UTINYINT,
    sats_used    SMALLINT, sats_visible SMALLINT,
    hdop         DOUBLE, h_acc_m DOUBLE, v_acc_m DOUBLE,
    utc_acc_ms   INTEGER,
    source_flags UTINYINT, frame_flags USMALLINT
);

CREATE TABLE imu (
    vehicle_id VARCHAR NOT NULL,
    content_root VARCHAR, boot_id VARCHAR, mono_ms UINTEGER, seq UINTEGER,
    observed_at  TIMESTAMP,
    window_ms    USMALLINT, accel_rms_mg USMALLINT,
    accel_peak_x_mg SMALLINT, accel_peak_y_mg SMALLINT, accel_peak_z_mg SMALLINT,
    gyro_peak_dps DOUBLE, variance USMALLINT, sample_count USMALLINT,
    event_flags  UTINYINT, frame_flags USMALLINT
);

CREATE TABLE obd (
    vehicle_id VARCHAR NOT NULL,
    content_root VARCHAR, boot_id VARCHAR, mono_ms UINTEGER, seq UINTEGER,
    observed_at  TIMESTAMP,
    speed_kph    SMALLINT, rpm SMALLINT, throttle_pct SMALLINT, load_pct SMALLINT,
    coolant_c    SMALLINT, intake_c SMALLINT,
    fuel_pressure_kpa INTEGER, timing_advance_deg SMALLINT,
    pid_error_count UTINYINT, pids_requested UINTEGER, pids_answered UINTEGER,
    poll_cadence_ms INTEGER, frame_flags USMALLINT
);

CREATE TABLE boost (
    vehicle_id VARCHAR NOT NULL,
    content_root VARCHAR, boot_id VARCHAR, mono_ms UINTEGER, seq UINTEGER,
    observed_at  TIMESTAMP,
    map_kpa      USMALLINT, baro_kpa UTINYINT, maf_cgps USMALLINT,
    lambda_e4    USMALLINT, abs_load_raw USMALLINT, ambient_c TINYINT,
    stft_pct     TINYINT, ltft_pct TINYINT,
    fuel_level_pct UTINYINT, pedal_pct UTINYINT,
    boost_psi    DOUBLE, lambda_ratio DOUBLE,
    pids_requested UINTEGER, pids_answered UINTEGER, poll_cadence_ms USMALLINT
);

CREATE TABLE status (
    vehicle_id VARCHAR NOT NULL,
    content_root VARCHAR, boot_id VARCHAR, mono_ms UINTEGER, seq UINTEGER,
    observed_at  TIMESTAMP,
    battery_mv   INTEGER, sd_write_errors INTEGER, sd_free_mib INTEGER,
    device_temp_c SMALLINT, rssi_dbm SMALLINT,
    ext_sensor1  INTEGER, ext_sensor2 INTEGER,
    health_state UTINYINT, reboot_count UTINYINT
);

CREATE TABLE transition (
    vehicle_id VARCHAR NOT NULL,
    content_root VARCHAR, boot_id VARCHAR, mono_ms UINTEGER, seq UINTEGER,
    observed_at  TIMESTAMP,
    region UTINYINT, from_state UTINYINT, to_state UTINYINT, trigger_event UTINYINT,
    reason_code UTINYINT, policy_version UTINYINT,
    start_score DOUBLE, stop_score DOUBLE, wake_cause UINTEGER
);

CREATE TABLE gap (
    vehicle_id VARCHAR NOT NULL,
    content_root VARCHAR, boot_id VARCHAR, seq UINTEGER,
    started_at   TIMESTAMP, duration_ms UINTEGER,
    expected_samples USMALLINT, cause UTINYINT
);

-- Wall-clock observations, one row per source per reading (format v3 section 4.12).
--
-- There is no observed_at column on purpose: a row whose job is to establish the
-- time cannot be stamped with the time it is establishing. mono_ms is the device
-- clock at the reading and implied_basis_ms is utc_ms minus it -- the UTC of
-- monotonic zero this source implies, which is what makes two sources comparable
-- and drift within one visible.
--
-- adopted marks the observation the device used for the manifest's utc_basis_ms,
-- so a reader can see what was chosen as well as what was available.
CREATE TABLE time_obs (
    vehicle_id VARCHAR NOT NULL,
    content_root VARCHAR, boot_id VARCHAR, seq UINTEGER,
    mono_ms    UINTEGER,
    utc_ms     UBIGINT,
    implied_basis_ms UBIGINT,
    accuracy_ms UINTEGER,
    source     VARCHAR,
    adopted    BOOLEAN
);

-- The owner's tune records, copied from the vehicle registry when the store is built (the
-- registry is the one place they are written). tuned_at is the start of the tune's day,
-- UTC. A store with no tune records simply has no rows here.
CREATE TABLE tune (
    vehicle_id VARCHAR NOT NULL,
    tune_id    VARCHAR NOT NULL,
    tuned_at   TIMESTAMP NOT NULL,
    note       VARCHAR
);
`

// bundleTables are every table the loader fills, in the order the appenders are opened.
// bundleTables is every table a bundle load writes to, and therefore every table
// that needs a DuckDB appender. A table missing from here has no appender, and the
// insert nil-dereferences inside the driver the first time a bundle carries that
// record -- which is how time_obs took the store down in a crash loop on
// 2026-10-08. TestEveryTableHasAnAppender ties this list to the schema so the two
// cannot drift again.
var bundleTables = []string{"bundles", "position", "imu", "obd", "boost", "status", "transition", "gap", "time_obs", "tune"}

// sampleTables are the tables physically ordered by (vehicle_id, boot_id,
// mono_ms) once a load finishes. Sorting is what lets DuckDB's min/max zone
// maps skip row groups on a time-range predicate and what keeps an ASOF join a
// streaming merge rather than a hash build.
var sampleTables = []string{"position", "imu", "obd", "boost", "status", "transition", "time_obs"}

// viewsSQL are the canned analysis surfaces.
//
// Every one of them is per vehicle: vehicle_id is the first output column, every
// join and ASOF join carries vehicle_id equality next to boot_id, and every
// window and grouping partitions by it. A caller selects a car with
// WHERE vehicle_id = '<hex>' on any view, and because nothing was computed
// across cars, filtering the output is exact rather than an approximation.
//
// v_telemetry anchors on the OBD poll and attaches the most recent boost and
// GNSS row at or before it. The *_age_ms columns are the honest part: an ASOF
// join always finds *something*, so how stale it is has to travel with the row,
// and a consumer that wants only fresh readings filters on the age.
const viewsSQL = `
CREATE VIEW v_telemetry AS
SELECT
    o.vehicle_id, o.boot_id, o.mono_ms, o.observed_at,
    o.speed_kph, o.rpm, o.throttle_pct, o.load_pct, o.coolant_c, o.intake_c,
    o.timing_advance_deg,
    b.boost_psi, b.map_kpa, b.baro_kpa, b.lambda_ratio, b.stft_pct, b.ltft_pct, b.maf_cgps,
    (o.mono_ms - b.mono_ms) AS boost_age_ms,
    p.speed_mps * 3.6       AS gnss_speed_kph,
    p.lat, p.lon, p.fix_type,
    (o.mono_ms - p.mono_ms) AS gnss_age_ms
FROM obd o
ASOF LEFT JOIN boost b    ON o.vehicle_id = b.vehicle_id AND o.boot_id = b.boot_id
    AND o.mono_ms >= b.mono_ms
ASOF LEFT JOIN position p ON o.vehicle_id = p.vehicle_id AND o.boot_id = p.boot_id
    AND o.mono_ms >= p.mono_ms
    AND coalesce(p.source_flags, 0) & 32 = 0;

CREATE VIEW v_reproducibility AS
SELECT vehicle_id, content_root, origin, decoder_ver, output_digest, reproduced,
       n_position, n_imu, n_obd, n_boost, n_status, n_transition, n_gap, warnings
FROM bundles;

-- The vehicles the store holds data for. This is the list a vehicle selector
-- offers; display names live in cairn-server's registry, not here.
CREATE VIEW v_vehicles AS
WITH obs AS (
    SELECT vehicle_id, observed_at FROM position
    UNION ALL SELECT vehicle_id, observed_at FROM obd
    UNION ALL SELECT vehicle_id, observed_at FROM imu
    UNION ALL SELECT vehicle_id, observed_at FROM status
),
span AS (
    SELECT vehicle_id, min(observed_at) AS first_observed_at, max(observed_at) AS last_observed_at
    FROM obs GROUP BY vehicle_id
),
held AS (
    SELECT vehicle_id, count(*) AS bundles, count(DISTINCT boot_id) AS boots
    FROM bundles GROUP BY vehicle_id
)
SELECT h.vehicle_id, h.bundles, h.boots, s.first_observed_at, s.last_observed_at
FROM held h
LEFT JOIN span s USING (vehicle_id);

-- Per-boot summary: duration, max speed, sample counts, gaps, warnings.
CREATE VIEW v_drive_summary AS
WITH drive AS (
    SELECT vehicle_id, boot_id,
           (max(mono_ms) - min(mono_ms)) / 1000.0 AS duration_s,
           max(speed_kph) AS max_speed_kph,
           max(rpm) AS max_rpm,
           count(*) AS obd_samples
    FROM obd GROUP BY vehicle_id, boot_id
),
gnss AS (
    SELECT vehicle_id, boot_id,
           count(*) FILTER (WHERE coalesce(source_flags, 0) & 32 = 0) AS gnss_samples,
           count(*) FILTER (WHERE coalesce(source_flags, 0) & 32 = 0 AND fix_type > 0) AS fix_samples,
           count(*) FILTER (WHERE coalesce(source_flags, 0) & 32 != 0) AS phone_samples
    FROM position GROUP BY vehicle_id, boot_id
),
gaps AS (
    SELECT vehicle_id, boot_id,
           count(*) AS gap_count,
           coalesce(sum(duration_ms), 0) AS gap_duration_ms
    FROM gap GROUP BY vehicle_id, boot_id
),
warns AS (
    SELECT vehicle_id, boot_id,
           string_agg(DISTINCT warnings, '; ') FILTER (WHERE warnings != '') AS warnings
    FROM bundles GROUP BY vehicle_id, boot_id
)
SELECT d.vehicle_id, d.boot_id, d.duration_s, d.max_speed_kph, d.max_rpm, d.obd_samples,
       coalesce(g.gnss_samples, 0) AS gnss_samples,
       coalesce(g.fix_samples, 0) AS fix_samples,
       coalesce(g.phone_samples, 0) AS phone_samples,
       coalesce(gp.gap_count, 0) AS gap_count,
       coalesce(gp.gap_duration_ms, 0) AS gap_duration_ms,
       w.warnings
FROM drive d
LEFT JOIN gnss g   ON g.vehicle_id = d.vehicle_id AND g.boot_id = d.boot_id
LEFT JOIN gaps gp  ON gp.vehicle_id = d.vehicle_id AND gp.boot_id = d.boot_id
LEFT JOIN warns w  ON w.vehicle_id = d.vehicle_id AND w.boot_id = d.boot_id;

-- One row per (vehicle, boot) with whatever was observed, not only OBD: a
-- drive with no ECU answering still happened. This is what cairn-server's
-- trip_summary publisher reads. Distance sums great-circle steps between
-- consecutive device fixes no more than 5 s apart — the decoder's own bridging
-- rule — so an interruption is never crossed with a straight line.
CREATE VIEW v_trip_summary AS
WITH obs AS (
    SELECT vehicle_id, boot_id, mono_ms, observed_at FROM position
    UNION ALL SELECT vehicle_id, boot_id, mono_ms, observed_at FROM obd
    UNION ALL SELECT vehicle_id, boot_id, mono_ms, observed_at FROM imu
    UNION ALL SELECT vehicle_id, boot_id, mono_ms, observed_at FROM status
),
t_span AS (
    SELECT vehicle_id, boot_id,
           min(observed_at) AS started_at, max(observed_at) AS ended_at,
           CAST(max(mono_ms) AS BIGINT) - CAST(min(mono_ms) AS BIGINT) AS duration_ms
    FROM obs GROUP BY vehicle_id, boot_id
),
t_fixes AS (
    SELECT vehicle_id, boot_id, mono_ms, lat, lon, speed_mps,
           lag(mono_ms) OVER w AS prev_ms, lag(lat) OVER w AS prev_lat, lag(lon) OVER w AS prev_lon
    FROM position
    WHERE fix_type > 0 AND coalesce(source_flags, 0) & 32 = 0
    WINDOW w AS (PARTITION BY vehicle_id, boot_id ORDER BY mono_ms, seq)
),
t_gnss AS (
    SELECT vehicle_id, boot_id,
           count(*) AS fix_samples,
           max(speed_mps) AS max_gnss_speed_mps,
           coalesce(sum(CASE WHEN prev_ms IS NOT NULL AND mono_ms - prev_ms <= 5000
               THEN 2 * 6371000.0 * asin(sqrt(
                   pow(sin(radians(lat - prev_lat) / 2), 2) +
                   cos(radians(prev_lat)) * cos(radians(lat)) * pow(sin(radians(lon - prev_lon) / 2), 2)))
               ELSE 0 END), 0) AS distance_m
    FROM t_fixes GROUP BY vehicle_id, boot_id
),
t_pos AS (
    SELECT vehicle_id, boot_id,
           count(*) FILTER (WHERE coalesce(source_flags, 0) & 32 = 0) AS gnss_samples
    FROM position GROUP BY vehicle_id, boot_id
),
t_eng AS (
    SELECT vehicle_id, boot_id, count(*) AS obd_samples,
           max(speed_kph) AS max_obd_speed_kph, max(rpm) AS max_rpm
    FROM obd GROUP BY vehicle_id, boot_id
),
t_bst AS (
    SELECT vehicle_id, boot_id, count(*) AS boost_samples
    FROM boost GROUP BY vehicle_id, boot_id
),
t_gaps AS (
    SELECT vehicle_id, boot_id, count(*) AS gap_count,
           coalesce(sum(duration_ms), 0) AS gap_duration_ms
    FROM gap GROUP BY vehicle_id, boot_id
),
t_held AS (
    SELECT vehicle_id, boot_id,
           string_agg(bundle_id, ',' ORDER BY bundle_id) AS bundle_ids,
           count(*) AS bundle_count,
           min(device_id) AS device_id,
           max(decoder_ver) AS decoder_version
    FROM bundles GROUP BY vehicle_id, boot_id
)
SELECT s.vehicle_id, s.boot_id, h.device_id,
       s.started_at, s.ended_at, s.duration_ms,
       g.distance_m, g.max_gnss_speed_mps,
       e.max_obd_speed_kph, e.max_rpm,
       coalesce(e.obd_samples, 0) AS obd_samples,
       coalesce(p.gnss_samples, 0) AS gnss_samples,
       coalesce(g.fix_samples, 0) AS fix_samples,
       coalesce(b.boost_samples, 0) AS boost_samples,
       coalesce(gp.gap_count, 0) AS gap_count,
       coalesce(gp.gap_duration_ms, 0) AS gap_duration_ms,
       h.bundle_ids, h.bundle_count, h.decoder_version
FROM t_span s
LEFT JOIN t_gnss g  ON g.vehicle_id = s.vehicle_id AND g.boot_id = s.boot_id
LEFT JOIN t_pos p   ON p.vehicle_id = s.vehicle_id AND p.boot_id = s.boot_id
LEFT JOIN t_eng e   ON e.vehicle_id = s.vehicle_id AND e.boot_id = s.boot_id
LEFT JOIN t_bst b   ON b.vehicle_id = s.vehicle_id AND b.boot_id = s.boot_id
LEFT JOIN t_gaps gp ON gp.vehicle_id = s.vehicle_id AND gp.boot_id = s.boot_id
LEFT JOIN t_held h  ON h.vehicle_id = s.vehicle_id AND h.boot_id = s.boot_id;

-- STFT/LTFT binned by RPM (500 steps) and load (10% steps). For an ethanol
-- blend the long-term trim is the honest signal: this is the view that
-- estimates drift from the baseline tune. Filters on boost_age_ms because an
-- ASOF join always finds something — a trim from a minute ago is not a reading
-- at this operating point.
CREATE VIEW v_trim_map AS
SELECT
    o.vehicle_id,
    o.boot_id,
    (o.rpm // 500) * 500 AS rpm_bin,
    (o.load_pct // 10) * 10 AS load_bin,
    avg(b.stft_pct) AS avg_stft,
    avg(b.ltft_pct) AS avg_ltft,
    count(*) AS samples
FROM obd o
ASOF JOIN boost b ON o.vehicle_id = b.vehicle_id AND o.boot_id = b.boot_id
    AND o.mono_ms >= b.mono_ms
WHERE (o.mono_ms - b.mono_ms) < 2000
  AND o.rpm IS NOT NULL
  AND o.load_pct IS NOT NULL
  AND b.stft_pct IS NOT NULL
GROUP BY o.vehicle_id, o.boot_id, rpm_bin, load_bin;

-- Boost pressure against RPM, excluding stale and MAP-saturated readings.
-- MAP >= 255 kPa is the sensor's ceiling, not a measurement.
CREATE VIEW v_boost_curve AS
SELECT
    o.vehicle_id, o.boot_id, o.mono_ms, o.rpm,
    b.boost_psi, b.map_kpa, b.baro_kpa,
    o.mono_ms - b.mono_ms AS boost_age_ms
FROM obd o
ASOF JOIN boost b ON o.vehicle_id = b.vehicle_id AND o.boot_id = b.boot_id
    AND o.mono_ms >= b.mono_ms
WHERE o.rpm IS NOT NULL
  AND b.boost_psi IS NOT NULL
  AND (o.mono_ms - b.mono_ms) < 2000
  AND (b.map_kpa IS NULL OR b.map_kpa < 255);

-- Wide-open-throttle pull detection via gap-and-island grouping. A pull is a
-- contiguous run of throttle >= 70% where RPM rises by at least 500 over at
-- least two OBD samples. Boost, lambda and trim stats come from the boost
-- readings that fall in each pull's time window, excluding MAP-saturated rows.
CREATE VIEW v_pulls AS
WITH numbered AS (
    SELECT vehicle_id, boot_id, mono_ms, rpm, throttle_pct, load_pct, speed_kph,
           ROW_NUMBER() OVER (PARTITION BY vehicle_id, boot_id ORDER BY mono_ms) AS rn
    FROM obd
    WHERE throttle_pct IS NOT NULL AND rpm IS NOT NULL
),
wot AS (
    SELECT *,
           rn - ROW_NUMBER() OVER (PARTITION BY vehicle_id, boot_id ORDER BY mono_ms) AS island
    FROM numbered
    WHERE throttle_pct >= 70
),
bounds AS (
    SELECT vehicle_id, boot_id, island,
           min(mono_ms) AS start_ms,
           max(mono_ms) AS end_ms,
           min(rpm) AS min_rpm,
           max(rpm) AS max_rpm,
           max(speed_kph) AS max_speed_kph,
           avg(load_pct) AS avg_load,
           count(*) AS obd_samples
    FROM wot
    GROUP BY vehicle_id, boot_id, island
    HAVING max(rpm) > min(rpm) + 500
       AND count(*) >= 2
),
pull_boost AS (
    SELECT p.vehicle_id, p.boot_id, p.island,
           max(b.boost_psi) AS peak_boost_psi,
           avg(b.lambda_ratio) FILTER (WHERE b.lambda_ratio IS NOT NULL) AS avg_lambda,
           avg(b.stft_pct) FILTER (WHERE b.stft_pct IS NOT NULL) AS avg_stft,
           avg(b.ltft_pct) FILTER (WHERE b.ltft_pct IS NOT NULL) AS avg_ltft
    FROM bounds p
    JOIN boost b ON b.vehicle_id = p.vehicle_id
                AND b.boot_id = p.boot_id
                AND b.mono_ms BETWEEN p.start_ms AND p.end_ms
                AND (b.map_kpa IS NULL OR b.map_kpa < 255)
    GROUP BY p.vehicle_id, p.boot_id, p.island
)
SELECT b.vehicle_id, b.boot_id, b.start_ms, b.end_ms,
       (b.end_ms - b.start_ms) / 1000.0 AS duration_s,
       b.min_rpm, b.max_rpm, b.max_speed_kph, b.avg_load, b.obd_samples,
       pb.peak_boost_psi, pb.avg_lambda, pb.avg_stft, pb.avg_ltft
FROM bounds b
LEFT JOIN pull_boost pb ON pb.vehicle_id = b.vehicle_id AND pb.boot_id = b.boot_id
    AND pb.island = b.island;

-- OBD speed against GNSS speed per sample. A persistent ratio is a tyre-size or
-- speedometer error; a growing one is a sensor. Only rows with a 3D fix and a
-- GNSS reading within 5 s are included. Low speeds (< 5 kph) are excluded from
-- the ratio because the measurement noise dominates.
CREATE VIEW v_speed_agreement AS
SELECT
    o.vehicle_id,
    o.boot_id,
    o.mono_ms,
    o.speed_kph AS obd_speed_kph,
    p.speed_mps * 3.6 AS gnss_speed_kph,
    CASE WHEN o.speed_kph > 5 AND p.speed_mps * 3.6 > 5
         THEN o.speed_kph / (p.speed_mps * 3.6)
         ELSE NULL END AS ratio,
    o.mono_ms - p.mono_ms AS gnss_age_ms
FROM obd o
ASOF JOIN position p ON o.vehicle_id = p.vehicle_id AND o.boot_id = p.boot_id
    AND o.mono_ms >= p.mono_ms
    AND coalesce(p.source_flags, 0) & 32 = 0
WHERE o.speed_kph IS NOT NULL
  AND p.speed_mps IS NOT NULL
  AND p.fix_type > 0
  AND (o.mono_ms - p.mono_ms) < 5000;

-- Internal vs phone GNSS comparison. Joined by measurement time within a 500 ms
-- window; reports per-boot disagreement. Works only when both sources are present.
CREATE VIEW v_gnss_sources AS
SELECT
    i.vehicle_id, i.boot_id, i.mono_ms,
    i.lat AS internal_lat, i.lon AS internal_lon, i.fix_type AS internal_fix,
    i.h_acc_m AS internal_hacc, i.speed_mps AS internal_speed,
    p.lat AS phone_lat, p.lon AS phone_lon, p.fix_type AS phone_fix,
    p.h_acc_m AS phone_hacc, p.speed_mps AS phone_speed,
    ABS(i.mono_ms - p.mono_ms) AS time_offset_ms
FROM position i
ASOF JOIN position p ON i.vehicle_id = p.vehicle_id AND i.boot_id = p.boot_id
    AND i.mono_ms >= p.mono_ms
    AND coalesce(p.source_flags, 0) & 32 != 0
WHERE coalesce(i.source_flags, 0) & 32 = 0
  AND i.fix_type > 0
  AND p.fix_type > 0
  AND ABS(i.mono_ms - p.mono_ms) < 500;

-- When each boot began, as far as the store can tell: its first sample that carries a UTC
-- estimate. A boot with none has no place on a calendar and takes no part in a comparison
-- over time.
CREATE VIEW v_boot_start AS
SELECT vehicle_id, boot_id, min(observed_at) AS started_at
FROM (SELECT vehicle_id, boot_id, observed_at FROM boost
      UNION ALL SELECT vehicle_id, boot_id, observed_at FROM obd) AS s
WHERE observed_at IS NOT NULL
GROUP BY vehicle_id, boot_id;

-- One observation per row for the four numbers the owner compares across a tune, each
-- stamped with when its boot began. The unit of observation differs on purpose:
--   boost_psi, lambda  one per wide-open-throttle pull (v_pulls): its peak boost and its
--                      mean lambda. Idle and cruise readings say nothing about a tune.
--   ltft_pct, stft_pct one per boot: the median trim over the boot, kept only when the boot
--                      holds at least 20 readings, so one long drive does not outweigh ten
--                      short ones and a drive that barely started counts for nothing.
-- metric is the engine profile's signal key.
CREATE VIEW v_metric_samples AS
SELECT p.vehicle_id, p.boot_id, 'boost_psi' AS metric, p.peak_boost_psi AS value, s.started_at
FROM v_pulls p JOIN v_boot_start s ON s.vehicle_id = p.vehicle_id AND s.boot_id = p.boot_id
WHERE p.peak_boost_psi IS NOT NULL
UNION ALL
SELECT p.vehicle_id, p.boot_id, 'lambda', p.avg_lambda, s.started_at
FROM v_pulls p JOIN v_boot_start s ON s.vehicle_id = p.vehicle_id AND s.boot_id = p.boot_id
WHERE p.avg_lambda IS NOT NULL
UNION ALL
SELECT b.vehicle_id, b.boot_id, 'ltft_pct', median(b.ltft_pct), s.started_at
FROM boost b JOIN v_boot_start s ON s.vehicle_id = b.vehicle_id AND s.boot_id = b.boot_id
WHERE b.ltft_pct IS NOT NULL
GROUP BY b.vehicle_id, b.boot_id, s.started_at
HAVING count(*) >= 20
UNION ALL
SELECT b.vehicle_id, b.boot_id, 'stft_pct', median(b.stft_pct), s.started_at
FROM boost b JOIN v_boot_start s ON s.vehicle_id = b.vehicle_id AND s.boot_id = b.boot_id
WHERE b.stft_pct IS NOT NULL
GROUP BY b.vehicle_id, b.boot_id, s.started_at
HAVING count(*) >= 20;

-- Before and after, per tune and metric. "Before" is the stretch under the previous tune
-- (from that tune's day up to this one, or from the start of the data for the first tune)
-- and "after" is the stretch under this one (up to the next tune, or to the end). A median
-- over everything before would mix two earlier tunes into one baseline. Every tune gets one
-- row per metric, with NULL medians and zero counts where the data is not there yet, so a
-- reader never has to tell "no row" from "no data".
CREATE VIEW v_tune_effect AS
WITH tw AS (
    SELECT vehicle_id, tune_id, tuned_at,
           coalesce(lag(tuned_at) OVER w, TIMESTAMP '1970-01-01') AS window_from,
           coalesce(lead(tuned_at) OVER w, TIMESTAMP '9999-12-31') AS window_to
    FROM tune
    WINDOW w AS (PARTITION BY vehicle_id ORDER BY tuned_at, tune_id)
)
SELECT t.vehicle_id, t.tune_id, m.metric,
       median(s.value) FILTER (WHERE s.started_at >= t.window_from AND s.started_at < t.tuned_at) AS before_median,
       median(s.value) FILTER (WHERE s.started_at >= t.tuned_at AND s.started_at < t.window_to)   AS after_median,
       count(*) FILTER (WHERE s.started_at >= t.window_from AND s.started_at < t.tuned_at)        AS before_n,
       count(*) FILTER (WHERE s.started_at >= t.tuned_at AND s.started_at < t.window_to)          AS after_n
FROM tw t
CROSS JOIN (VALUES ('boost_psi'), ('lambda'), ('ltft_pct'), ('stft_pct')) AS m(metric)
LEFT JOIN v_metric_samples s ON s.vehicle_id = t.vehicle_id AND s.metric = m.metric
GROUP BY t.vehicle_id, t.tune_id, m.metric;

-- The raw statistics behind the health summary: the last 14 days of a car's data against
-- the stretch before them. "Last" is relative to the car's most recent observation, not to
-- the clock, so a car that has sat for a month is described by the drives it last made
-- rather than by an empty fortnight. The baseline starts at the latest tune: a tune moves
-- fuel trim on purpose, and comparing against the car before it would report the tune as
-- a fault. cairn-server turns these into sentences, because the limits that make a number
-- "normal" belong to the engine profile and not to the store.
CREATE VIEW v_health_stats AS
WITH last AS (
    SELECT vehicle_id, max(started_at) AS last_at FROM v_metric_samples GROUP BY vehicle_id
),
cur AS (
    SELECT vehicle_id, max(tuned_at) AS tuned_at FROM tune GROUP BY vehicle_id
)
SELECT s.vehicle_id, s.metric,
       median(s.value) FILTER (WHERE s.started_at > l.last_at - INTERVAL 14 DAY) AS recent_median,
       count(*) FILTER (WHERE s.started_at > l.last_at - INTERVAL 14 DAY)        AS recent_n,
       median(s.value) FILTER (WHERE s.started_at <= l.last_at - INTERVAL 14 DAY
                                 AND s.started_at >= coalesce(c.tuned_at, TIMESTAMP '1970-01-01')) AS baseline_median,
       count(*) FILTER (WHERE s.started_at <= l.last_at - INTERVAL 14 DAY
                          AND s.started_at >= coalesce(c.tuned_at, TIMESTAMP '1970-01-01'))        AS baseline_n,
       l.last_at AS last_observed_at,
       c.tuned_at AS tuned_at
FROM v_metric_samples s
JOIN last l ON l.vehicle_id = s.vehicle_id
LEFT JOIN cur c ON c.vehicle_id = s.vehicle_id
GROUP BY s.vehicle_id, s.metric, l.last_at, c.tuned_at;

-- One row per trip with the calendar period it belongs to, for a caller that groups
-- or filters by year, quarter, month or week itself. A trip belongs to the period
-- (UTC calendar day, ISO week starting Monday) of its started_at, the first thing
-- observed on any source, and all of it counts there, including the part after a
-- midnight, month or year boundary: a drive is not split. observed_at is a
-- timezone-less UTC estimate, so no session TimeZone setting moves a trip across
-- a boundary. A trip with no wall-clock time at all (started_at NULL) belongs to
-- no period and is not listed. Distance, duration and the speed maxima are
-- v_trip_summary's own, not recomputed.
CREATE VIEW v_trip_period AS
SELECT vehicle_id, boot_id, started_at, ended_at,
       CAST(started_at AS DATE) AS started_on,
       CAST(date_trunc('week', started_at) AS DATE) AS week_start,
       CAST(date_trunc('month', started_at) AS DATE) AS month_start,
       CAST(date_trunc('quarter', started_at) AS DATE) AS quarter_start,
       CAST(date_trunc('year', started_at) AS DATE) AS year_start,
       duration_ms, distance_m,
       max_obd_speed_kph,
       max_gnss_speed_mps * 3.6 AS max_gnss_speed_kph
FROM v_trip_summary
WHERE started_at IS NOT NULL;

-- A view cannot take a parameter, so the period summary for any date range is a
-- table macro: SELECT * FROM period_summary('2026-03-01', '2026-04-01'). The range
-- is [from_day, to_day): from_day is included and to_day is the first day after,
-- so adjacent ranges (a month, the next month) neither overlap nor leave a gap; a
-- custom "1 to 10 March" is ('2026-03-01', '2026-03-11'). One row per vehicle that
-- has a trip in the range; a vehicle with none has no row, which a consumer reads
-- as zero. max_obd_speed_kph is v_drive_summary's max_speed_kph. Group a year,
-- quarter, month or week by selecting v_trip_period on its *_start column instead.
CREATE MACRO period_summary(from_day, to_day) AS TABLE
SELECT vehicle_id,
       count(*) AS trips,
       CAST(coalesce(sum(duration_ms), 0) AS BIGINT) AS duration_ms,
       coalesce(sum(distance_m), 0) AS distance_m,
       max(max_obd_speed_kph) AS max_obd_speed_kph,
       max(max_gnss_speed_kph) AS max_gnss_speed_kph
FROM v_trip_period
WHERE started_at >= CAST(from_day AS TIMESTAMP) AND started_at < CAST(to_day AS TIMESTAMP)
GROUP BY vehicle_id;
`

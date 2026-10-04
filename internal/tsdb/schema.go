package tsdb

// Every sample table is keyed on (boot_id, mono_ms), never on wall-clock UTC.
// Ordering truth in a Cairn bundle is (boot_id, seq); UTC is an estimate that
// carries its own uncertainty. mono_ms is the boot-relative clock that the
// device stamped on the frame, so it orders rows within a boot exactly, and
// observed_at rides along as an annotation for anyone who wants to plot against
// a calendar.
//
// Column types match the decoder's Go types one to one. The appender is strict
// about that, and it keeps a narrow column narrow: a u8 stays a UTINYINT rather
// than widening to BIGINT and costing memory bandwidth on every scan.
const schemaSQL = `
CREATE TABLE bundles (
    content_root   VARCHAR PRIMARY KEY,
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
    warnings       VARCHAR
);

CREATE TABLE position (
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
    content_root VARCHAR, boot_id VARCHAR, mono_ms UINTEGER, seq UINTEGER,
    observed_at  TIMESTAMP,
    window_ms    USMALLINT, accel_rms_mg USMALLINT,
    accel_peak_x_mg SMALLINT, accel_peak_y_mg SMALLINT, accel_peak_z_mg SMALLINT,
    gyro_peak_dps DOUBLE, variance USMALLINT, sample_count USMALLINT,
    event_flags  UTINYINT, frame_flags USMALLINT
);

CREATE TABLE obd (
    content_root VARCHAR, boot_id VARCHAR, mono_ms UINTEGER, seq UINTEGER,
    observed_at  TIMESTAMP,
    speed_kph    SMALLINT, rpm SMALLINT, throttle_pct SMALLINT, load_pct SMALLINT,
    coolant_c    SMALLINT, intake_c SMALLINT,
    fuel_pressure_kpa INTEGER, timing_advance_deg SMALLINT,
    pid_error_count UTINYINT, pids_requested UINTEGER, pids_answered UINTEGER,
    poll_cadence_ms INTEGER, frame_flags USMALLINT
);

CREATE TABLE boost (
    content_root VARCHAR, boot_id VARCHAR, mono_ms UINTEGER, seq UINTEGER,
    observed_at  TIMESTAMP,
    map_kpa      USMALLINT, baro_kpa UTINYINT, maf_cgps USMALLINT,
    lambda_e4    USMALLINT, abs_load_raw USMALLINT, ambient_c TINYINT,
    stft_pct     TINYINT, ltft_pct TINYINT,
    fuel_level_pct UTINYINT,
    boost_psi    DOUBLE, lambda_ratio DOUBLE,
    pids_requested UINTEGER, pids_answered UINTEGER, poll_cadence_ms USMALLINT
);

CREATE TABLE status (
    content_root VARCHAR, boot_id VARCHAR, mono_ms UINTEGER, seq UINTEGER,
    observed_at  TIMESTAMP,
    battery_mv   INTEGER, sd_write_errors INTEGER, sd_free_mib INTEGER,
    device_temp_c SMALLINT, rssi_dbm SMALLINT,
    ext_sensor1  INTEGER, ext_sensor2 INTEGER,
    health_state UTINYINT, reboot_count UTINYINT
);

CREATE TABLE transition (
    content_root VARCHAR, boot_id VARCHAR, mono_ms UINTEGER, seq UINTEGER,
    observed_at  TIMESTAMP,
    region UTINYINT, from_state UTINYINT, to_state UTINYINT, trigger_event UTINYINT,
    reason_code UTINYINT, policy_version UTINYINT,
    start_score DOUBLE, stop_score DOUBLE, wake_cause UINTEGER
);

CREATE TABLE gap (
    content_root VARCHAR, boot_id VARCHAR, seq UINTEGER,
    started_at   TIMESTAMP, duration_ms UINTEGER,
    expected_samples USMALLINT, cause UTINYINT
);
`

// sampleTables are the tables physically ordered by (boot_id, mono_ms) once a
// load finishes. Sorting is what lets DuckDB's min/max zone maps skip row groups
// on a time-range predicate and what keeps an ASOF join a streaming merge
// rather than a hash build.
var sampleTables = []string{"position", "imu", "obd", "boost", "status", "transition"}

// viewsSQL are the canned analysis surfaces.
//
// v_telemetry anchors on the OBD poll and attaches the most recent boost and
// GNSS row at or before it. The *_age_ms columns are the honest part: an ASOF
// join always finds *something*, so how stale it is has to travel with the row,
// and a consumer that wants only fresh readings filters on the age.
const viewsSQL = `
-- Quality-filtered position: rejects zero-fixes, impossible speeds (>150 mph)
-- and poor geometry (HDOP >= 15). Every UI query uses this instead of the raw
-- position table so a single forgotten WHERE clause cannot leak phantoms.
CREATE VIEW v_position AS
SELECT * FROM position
WHERE lat != 0 AND lon != 0
  AND speed_mps < 67
  AND (hdop IS NULL OR hdop < 15);

CREATE VIEW v_telemetry AS
SELECT
    o.boot_id, o.mono_ms, o.observed_at,
    o.speed_kph, o.rpm, o.throttle_pct, o.load_pct, o.coolant_c, o.intake_c,
    o.timing_advance_deg,
    b.boost_psi, b.map_kpa, b.baro_kpa, b.lambda_ratio, b.stft_pct, b.ltft_pct, b.maf_cgps,
    (o.mono_ms - b.mono_ms) AS boost_age_ms,
    p.speed_mps * 3.6       AS gnss_speed_kph,
    p.lat, p.lon, p.fix_type,
    (o.mono_ms - p.mono_ms) AS gnss_age_ms
FROM obd o
ASOF LEFT JOIN boost b    ON o.boot_id = b.boot_id AND o.mono_ms >= b.mono_ms
ASOF LEFT JOIN v_position p ON o.boot_id = p.boot_id AND o.mono_ms >= p.mono_ms
    AND coalesce(p.source_flags, 0) & 32 = 0;

CREATE VIEW v_reproducibility AS
SELECT content_root, origin, decoder_ver, output_digest, reproduced,
       n_position, n_imu, n_obd, n_boost, n_status, n_transition, n_gap, warnings
FROM bundles;

-- Per-boot summary: duration, max speed, sample counts, gaps, warnings.
CREATE VIEW v_drive_summary AS
WITH drive AS (
    SELECT boot_id,
           (max(mono_ms) - min(mono_ms)) / 1000.0 AS duration_s,
           max(speed_kph) AS max_speed_kph,
           max(rpm) AS max_rpm,
           count(*) AS obd_samples
    FROM obd GROUP BY boot_id
),
gnss AS (
    SELECT boot_id,
           count(*) FILTER (WHERE coalesce(source_flags, 0) & 32 = 0) AS gnss_samples,
           count(*) FILTER (WHERE coalesce(source_flags, 0) & 32 = 0 AND fix_type > 0) AS fix_samples,
           count(*) FILTER (WHERE coalesce(source_flags, 0) & 32 != 0) AS phone_samples
    FROM position GROUP BY boot_id
),
gaps AS (
    SELECT boot_id,
           count(*) AS gap_count,
           coalesce(sum(duration_ms), 0) AS gap_duration_ms
    FROM gap GROUP BY boot_id
),
warns AS (
    SELECT boot_id,
           string_agg(DISTINCT warnings, '; ') FILTER (WHERE warnings != '') AS warnings
    FROM bundles GROUP BY boot_id
)
SELECT d.boot_id, d.duration_s, d.max_speed_kph, d.max_rpm, d.obd_samples,
       coalesce(g.gnss_samples, 0) AS gnss_samples,
       coalesce(g.fix_samples, 0) AS fix_samples,
       coalesce(g.phone_samples, 0) AS phone_samples,
       coalesce(gp.gap_count, 0) AS gap_count,
       coalesce(gp.gap_duration_ms, 0) AS gap_duration_ms,
       w.warnings
FROM drive d
LEFT JOIN gnss g USING (boot_id)
LEFT JOIN gaps gp USING (boot_id)
LEFT JOIN warns w USING (boot_id);

-- STFT/LTFT binned by RPM (500 steps) and load (10% steps). For an ethanol
-- blend the long-term trim is the honest signal: this is the view that
-- estimates drift from the baseline tune. Filters on boost_age_ms because an
-- ASOF join always finds something — a trim from a minute ago is not a reading
-- at this operating point.
CREATE VIEW v_trim_map AS
SELECT
    o.boot_id,
    (o.rpm // 500) * 500 AS rpm_bin,
    (o.load_pct // 10) * 10 AS load_bin,
    avg(b.stft_pct) AS avg_stft,
    avg(b.ltft_pct) AS avg_ltft,
    count(*) AS samples
FROM obd o
ASOF JOIN boost b ON o.boot_id = b.boot_id AND o.mono_ms >= b.mono_ms
WHERE (o.mono_ms - b.mono_ms) < 2000
  AND o.rpm IS NOT NULL
  AND o.load_pct IS NOT NULL
  AND b.stft_pct IS NOT NULL
GROUP BY o.boot_id, rpm_bin, load_bin;

-- Boost pressure against RPM, excluding stale and MAP-saturated readings.
-- MAP >= 255 kPa is the sensor's ceiling, not a measurement.
CREATE VIEW v_boost_curve AS
SELECT
    o.boot_id, o.mono_ms, o.rpm,
    b.boost_psi, b.map_kpa, b.baro_kpa,
    o.mono_ms - b.mono_ms AS boost_age_ms
FROM obd o
ASOF JOIN boost b ON o.boot_id = b.boot_id AND o.mono_ms >= b.mono_ms
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
    SELECT boot_id, mono_ms, rpm, throttle_pct, load_pct, speed_kph,
           ROW_NUMBER() OVER (PARTITION BY boot_id ORDER BY mono_ms) AS rn
    FROM obd
    WHERE throttle_pct IS NOT NULL AND rpm IS NOT NULL
),
wot AS (
    SELECT *,
           rn - ROW_NUMBER() OVER (PARTITION BY boot_id ORDER BY mono_ms) AS island
    FROM numbered
    WHERE throttle_pct >= 70
),
bounds AS (
    SELECT boot_id, island,
           min(mono_ms) AS start_ms,
           max(mono_ms) AS end_ms,
           min(rpm) AS min_rpm,
           max(rpm) AS max_rpm,
           max(speed_kph) AS max_speed_kph,
           avg(load_pct) AS avg_load,
           count(*) AS obd_samples
    FROM wot
    GROUP BY boot_id, island
    HAVING max(rpm) > min(rpm) + 500
       AND count(*) >= 2
),
pull_boost AS (
    SELECT p.boot_id, p.island,
           max(b.boost_psi) AS peak_boost_psi,
           avg(b.lambda_ratio) FILTER (WHERE b.lambda_ratio IS NOT NULL) AS avg_lambda,
           avg(b.stft_pct) FILTER (WHERE b.stft_pct IS NOT NULL) AS avg_stft,
           avg(b.ltft_pct) FILTER (WHERE b.ltft_pct IS NOT NULL) AS avg_ltft
    FROM bounds p
    JOIN boost b ON b.boot_id = p.boot_id
                AND b.mono_ms BETWEEN p.start_ms AND p.end_ms
                AND (b.map_kpa IS NULL OR b.map_kpa < 255)
    GROUP BY p.boot_id, p.island
)
SELECT b.boot_id, b.start_ms, b.end_ms,
       (b.end_ms - b.start_ms) / 1000.0 AS duration_s,
       b.min_rpm, b.max_rpm, b.max_speed_kph, b.avg_load, b.obd_samples,
       pb.peak_boost_psi, pb.avg_lambda, pb.avg_stft, pb.avg_ltft
FROM bounds b
LEFT JOIN pull_boost pb USING (boot_id, island);

-- OBD speed against GNSS speed per sample. A persistent ratio is a tyre-size or
-- speedometer error; a growing one is a sensor. Only rows with a 3D fix and a
-- GNSS reading within 5 s are included. Low speeds (< 5 kph) are excluded from
-- the ratio because the measurement noise dominates.
CREATE VIEW v_speed_agreement AS
SELECT
    o.boot_id,
    o.mono_ms,
    o.speed_kph AS obd_speed_kph,
    p.speed_mps * 3.6 AS gnss_speed_kph,
    CASE WHEN o.speed_kph > 5 AND p.speed_mps * 3.6 > 5
         THEN o.speed_kph / (p.speed_mps * 3.6)
         ELSE NULL END AS ratio,
    o.mono_ms - p.mono_ms AS gnss_age_ms
FROM obd o
ASOF JOIN v_position p ON o.boot_id = p.boot_id AND o.mono_ms >= p.mono_ms
    AND coalesce(p.source_flags, 0) & 32 = 0
WHERE o.speed_kph IS NOT NULL
  AND p.speed_mps IS NOT NULL
  AND p.fix_type > 0
  AND (o.mono_ms - p.mono_ms) < 5000;

-- Internal vs phone GNSS comparison. Joined by measurement time within a 500 ms
-- window; reports per-boot disagreement. Works only when both sources are present.
CREATE VIEW v_gnss_sources AS
SELECT
    i.boot_id, i.mono_ms,
    i.lat AS internal_lat, i.lon AS internal_lon, i.fix_type AS internal_fix,
    i.h_acc_m AS internal_hacc, i.speed_mps AS internal_speed,
    p.lat AS phone_lat, p.lon AS phone_lon, p.fix_type AS phone_fix,
    p.h_acc_m AS phone_hacc, p.speed_mps AS phone_speed,
    ABS(i.mono_ms - p.mono_ms) AS time_offset_ms
FROM position i
ASOF JOIN position p ON i.boot_id = p.boot_id AND i.mono_ms >= p.mono_ms
    AND coalesce(p.source_flags, 0) & 32 != 0
WHERE coalesce(i.source_flags, 0) & 32 = 0
  AND i.fix_type > 0
  AND p.fix_type > 0
  AND ABS(i.mono_ms - p.mono_ms) < 500;
`

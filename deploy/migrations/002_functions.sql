-- 002_functions.sql
-- Spatial helper functions for Cairn.

BEGIN;

-- find_nearest_place returns all places whose center is within max_distance_m
-- of the given point, ordered by distance ascending.
CREATE OR REPLACE FUNCTION find_nearest_place(
    lat            DOUBLE PRECISION,
    lon            DOUBLE PRECISION,
    max_distance_m DOUBLE PRECISION DEFAULT 500
)
RETURNS TABLE (
    place_id  UUID,
    name      TEXT,
    distance_m DOUBLE PRECISION
)
LANGUAGE sql STABLE
AS $$
    SELECT
        p.id        AS place_id,
        p.name,
        ST_Distance(
            p.location,
            ST_SetSRID(ST_MakePoint(lon, lat), 4326)::geography
        ) AS distance_m
    FROM places p
    WHERE ST_DWithin(
        p.location,
        ST_SetSRID(ST_MakePoint(lon, lat), 4326)::geography,
        max_distance_m
    )
    ORDER BY distance_m ASC;
$$;

-- trip_distance computes the total distance in meters along a trip's
-- location_samples, ordered by timestamp_ms.
CREATE OR REPLACE FUNCTION trip_distance(p_trip_id TEXT)
RETURNS DOUBLE PRECISION
LANGUAGE sql STABLE
AS $$
    SELECT COALESCE(SUM(seg_distance), 0)
    FROM (
        SELECT ST_Distance(
            location,
            LAG(location) OVER (ORDER BY timestamp_ms)
        ) AS seg_distance
        FROM location_samples
        WHERE trip_id = p_trip_id
          AND location IS NOT NULL
    ) segments;
$$;

COMMIT;

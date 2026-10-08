-- Cairn v3 schema, amendment: accelerator pedal position.
--
-- OBD_EXTENDED gained pedal_pct (PID 0x49) in its last reserved byte, so the
-- record is still 24 bytes. See contracts/format/v3 §4.11.2 for why this is not
-- the same signal as throttle_pct.
--
-- The short version: throttle_pct is PID 0x11, the throttle *plate* angle, and a
-- drive-by-wire ECU opens the plate as far as it decides rather than as far as
-- the pedal travelled. On an N20 it never exceeded 77% across a 1002 s drive and
-- read 32% during the sample that caught 8.6 psi at 4142 rpm. Only pedal position
-- says the driver asked for everything, which is the first thing any performance
-- analysis needs to establish.
--
-- Nullable with no default on purpose. Rows written before this column existed
-- must read as "not measured", and NULL is the only value that cannot be confused
-- with a real 0% pedal. The same trap exists one layer down in the record itself,
-- where the byte was previously reserved-zero: readers there have to consult the
-- pids_requested bitmap instead.

BEGIN;

ALTER TABLE norm.boost_samples
    ADD COLUMN pedal_pct SMALLINT;

COMMENT ON COLUMN norm.boost_samples.pedal_pct IS
    'Accelerator pedal position %, PID 0x49. Driver demand, not throttle plate '
    'angle (see throttle_pct on obd_samples). NULL means not measured.';

COMMIT;

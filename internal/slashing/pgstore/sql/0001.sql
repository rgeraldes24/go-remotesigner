-- Copyright 2020 ConsenSys AG.
-- Copyright 2026 The go-remotesigner Authors.
--
-- Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
-- the License. You may obtain a copy of the License at
--
-- http://www.apache.org/licenses/LICENSE-2.0
--
-- Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
-- an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
-- specific language governing permissions and limitations under the License.
--
-- SPDX-License-Identifier: Apache-2.0
--
-- Modified by The go-remotesigner Authors, 2026: Web3Signer's twelve migrations squashed into one QRL schema, with the
-- validators keyed by sha256(public key), BIGINT columns with range checks instead of NUMERIC(20), the high-watermark
-- triggers raising SQLSTATE RSW01, the RANDAO frontier table and the schema version 1.
-- Derived from Web3Signer
-- slashing-protection/src/main/resources/migrations/postgresql/V00001__initial.sql,
-- slashing-protection/src/main/resources/migrations/postgresql/V00002__removeUniqueConstraints.sql,
-- slashing-protection/src/main/resources/migrations/postgresql/V00003__addLowWatermark.sql,
-- slashing-protection/src/main/resources/migrations/postgresql/V00004__addGenesisValidatorsRoot.sql,
-- slashing-protection/src/main/resources/migrations/postgresql/V00005__xnor_source_target_low_watermark.sql,
-- slashing-protection/src/main/resources/migrations/postgresql/V00006__signed_data_indexes.sql,
-- slashing-protection/src/main/resources/migrations/postgresql/V00007__add_db_version.sql,
-- slashing-protection/src/main/resources/migrations/postgresql/V00008__signed_data_unique_constraints.sql,
-- slashing-protection/src/main/resources/migrations/postgresql/V00009__upsert_validators.sql,
-- slashing-protection/src/main/resources/migrations/postgresql/V00010__validator_enabled_status.sql,
-- slashing-protection/src/main/resources/migrations/postgresql/V00011__bigint_indexes.sql and
-- slashing-protection/src/main/resources/migrations/postgresql/V00012__add_highwatermark_metadata.sql
-- at commit 30af06dc975ba5b8ed0e17e53cba8683ca50ec02.

-- Schema version 1 of the go-remotesigner Postgres slashing-protection store. The migration runner (pgstore.Migrate)
-- applies it in one transaction under pg_advisory_lock(3, 0).

-- A 2,592-byte key is too large for a B-tree entry with room to spare (the limit is 2,704 bytes), so validators are
-- keyed by the SHA-256 of their public key (Web3Signer V00001 keys them by the raw key).
-- disabled_by_import marks a key that an interchange import keeps disabled: one it registered before writing its
-- history, or one whose element failed. A later clean import enables it; a key disabled on purpose (keymanager
-- DELETE, disable-validator) has enabled = false and disabled_by_import = false, and imports leave it disabled.
CREATE TABLE validators (
    id                 SERIAL PRIMARY KEY,
    pubkey_hash        BYTEA NOT NULL UNIQUE CHECK (octet_length(pubkey_hash) = 32),
    public_key         BYTEA NOT NULL CHECK (octet_length(public_key) = 2592),
    enabled            BOOLEAN NOT NULL DEFAULT true,
    disabled_by_import BOOLEAN NOT NULL DEFAULT false,
    CONSTRAINT enabled_or_disabled_by_import CHECK (NOT (enabled AND disabled_by_import))
);

-- Slots and epochs are uint64 in the protocol. BIGINT holds them up to 2^63 - 1; the store refuses larger values
-- before they reach the database, and the checks refuse negative ones.
CREATE TABLE signed_blocks (
    id           BIGSERIAL PRIMARY KEY,
    validator_id INTEGER NOT NULL REFERENCES validators (id),
    slot         BIGINT NOT NULL CHECK (slot >= 0),
    signing_root BYTEA CHECK (octet_length(signing_root) = 32),
    CONSTRAINT unique_signed_block UNIQUE (validator_id, slot)
);

CREATE TABLE signed_attestations (
    id           BIGSERIAL PRIMARY KEY,
    validator_id INTEGER NOT NULL REFERENCES validators (id),
    source_epoch BIGINT NOT NULL CHECK (source_epoch >= 0),
    target_epoch BIGINT NOT NULL CHECK (target_epoch >= 0),
    signing_root BYTEA CHECK (octet_length(signing_root) = 32),
    CONSTRAINT unique_signed_attestation UNIQUE (validator_id, target_epoch)
);

CREATE TABLE low_watermarks (
    validator_id INTEGER NOT NULL UNIQUE REFERENCES validators (id),
    slot         BIGINT CHECK (slot >= 0),
    target_epoch BIGINT CHECK (target_epoch >= 0),
    source_epoch BIGINT CHECK (source_epoch >= 0),
    CONSTRAINT both_epochs_set_or_null CHECK ((target_epoch IS NULL) = (source_epoch IS NULL))
);

CREATE TABLE metadata (
    id                      INTEGER PRIMARY KEY CHECK (id = 1),
    genesis_validators_root BYTEA NOT NULL CHECK (octet_length(genesis_validators_root) = 32),
    high_watermark_epoch    BIGINT CHECK (high_watermark_epoch >= 0),
    high_watermark_slot     BIGINT CHECK (high_watermark_slot >= 0),
    CONSTRAINT both_high_watermark_parts_set_or_null CHECK ((high_watermark_epoch IS NULL) = (high_watermark_slot IS NULL))
);

-- The high watermark must stay above every low watermark, and every low watermark at or below the high watermark
-- (Web3Signer V00012). The store checks both before it writes; these triggers also hold for writes made outside it.
CREATE FUNCTION check_high_watermarks() RETURNS TRIGGER AS $$
DECLARE
    max_slot  BIGINT;
    max_epoch BIGINT;
BEGIN
    SELECT MAX(slot), GREATEST(MAX(target_epoch), MAX(source_epoch)) INTO max_slot, max_epoch FROM low_watermarks;
    IF NEW.high_watermark_slot <= max_slot THEN
        RAISE EXCEPTION 'high_watermark_slot must be greater than every low-watermark slot' USING ERRCODE = 'RSW01';
    END IF;
    IF NEW.high_watermark_epoch <= max_epoch THEN
        RAISE EXCEPTION 'high_watermark_epoch must be greater than every low-watermark epoch' USING ERRCODE = 'RSW01';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER check_before_insert_or_update_high_watermarks
    BEFORE INSERT OR UPDATE ON metadata
    FOR EACH ROW EXECUTE FUNCTION check_high_watermarks();

CREATE FUNCTION check_low_watermarks() RETURNS TRIGGER AS $$
DECLARE
    high_slot  BIGINT;
    high_epoch BIGINT;
BEGIN
    SELECT MIN(high_watermark_slot), MIN(high_watermark_epoch) INTO high_slot, high_epoch FROM metadata;
    IF NEW.slot > high_slot THEN
        RAISE EXCEPTION 'low-watermark slot must not exceed high_watermark_slot' USING ERRCODE = 'RSW01';
    END IF;
    IF NEW.source_epoch > high_epoch OR NEW.target_epoch > high_epoch THEN
        RAISE EXCEPTION 'low-watermark epochs must not exceed high_watermark_epoch' USING ERRCODE = 'RSW01';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER check_before_insert_or_update_low_watermarks
    BEFORE INSERT OR UPDATE ON low_watermarks
    FOR EACH ROW EXECUTE FUNCTION check_low_watermarks();

-- The RANDAO frontier (m, R = x_m, last) of each validator: the deepest onion layer released and the slot of the
-- last release that moved it. Nothing else of the onion is ever stored.
CREATE TABLE randao_reveal_state (
    validator_id   INTEGER PRIMARY KEY REFERENCES validators (id),
    deepest_index  BIGINT NOT NULL CHECK (deepest_index >= 0),
    deepest_reveal BYTEA NOT NULL CHECK (octet_length(deepest_reveal) = 32),
    last_new_slot  BIGINT NOT NULL CHECK (last_new_slot >= 0),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE database_version (
    id      INTEGER PRIMARY KEY CHECK (id = 1),
    version INTEGER NOT NULL
);

INSERT INTO database_version (id, version) VALUES (1, 1);

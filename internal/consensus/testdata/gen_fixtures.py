# Copyright 2026 The go-remotesigner Authors.
# SPDX-License-Identifier: Apache-2.0

"""Hand-derived SSZ and signing-root fixtures for the consensus packages.

This is a second, independent implementation of hash_tree_root, written in
Python from the CC0 Ethereum consensus specs v1.5.0 (ssz/simple-serialize.md,
phase0 and altair containers, compute_domain, compute_signing_root) and the
builder specs, with the QRL sizes (ML-DSA-87 public key 2,592 bytes, signature
4,627 bytes, 64-byte addresses, signature lists instead of aggregate
signatures). It deliberately works differently from the Go code: it pads every
tree with real zero chunks instead of precomputed zero hashes, and it unpacks
bitfields into Python booleans before packing them again.

The Go tests compare against its output, so a bug has to appear in both
implementations to go unnoticed. Golden vectors generated from qrysm replace
these fixtures as the authority in a later milestone; until then they are the
cross-check.

Usage (Python 3.9 or later, standard library only), from this directory:

    python3 gen_fixtures.py

It rewrites containers.json and signing.json next to this file. The output is
deterministic.
"""

import hashlib
import json
import os

U64_MAX = 2**64 - 1
PUBKEY_LEN = 2592
SIGNATURE_LEN = 4627
ADDRESS_LEN = 64
MAX_ATTESTATION_SIGNATURES = 32  # Bitlist[32] and List[Signature, 32]
MAX_CONTRIBUTION_SIGNATURES = 128


# ---------------------------------------------------------------- SSZ ----

def sha256(data):
    return hashlib.sha256(data).digest()


def next_pow_of_two(n):
    p = 1
    while p < n:
        p *= 2
    return p


def pack(data):
    if len(data) % 32:
        data = data + b"\x00" * (32 - len(data) % 32)
    return [data[i:i + 32] for i in range(0, len(data), 32)]


def merkleize(chunks, limit=None):
    if limit is None:
        width = next_pow_of_two(len(chunks))
    else:
        if len(chunks) > limit:
            raise ValueError("input exceeds limit")
        width = next_pow_of_two(limit)
    layer = list(chunks) + [b"\x00" * 32] * (width - len(chunks))
    while len(layer) > 1:
        layer = [sha256(layer[i] + layer[i + 1]) for i in range(0, len(layer), 2)]
    return layer[0]


def mix_in_length(root, length):
    return sha256(root + length.to_bytes(32, "little"))


def uint64_root(v):
    return merkleize(pack(v.to_bytes(8, "little")))


def byte_vector_root(b):
    return merkleize(pack(b))


def bits_to_bytes(bits):
    out = [0] * ((len(bits) + 7) // 8)
    for i, bit in enumerate(bits):
        if bit:
            out[i // 8] |= 1 << (i % 8)
    return bytes(out)


def bitvector_root(raw, n):
    assert len(raw) == (n + 7) // 8
    bits = [(raw[i // 8] >> (i % 8)) & 1 for i in range(n)]
    return merkleize(pack(bits_to_bytes(bits)), limit=(n + 255) // 256)


def bitlist_root(raw, limit):
    # Decode the serialized bitlist: the highest set bit is the delimiter.
    bits = [(raw[i // 8] >> (i % 8)) & 1 for i in range(len(raw) * 8)]
    while bits and bits[-1] == 0:
        bits.pop()
    assert bits, "no delimiter"
    bits.pop()
    assert len(bits) <= limit
    return mix_in_length(merkleize(pack(bits_to_bytes(bits)), limit=(limit + 255) // 256), len(bits))


def composite_list_root(roots, limit):
    return mix_in_length(merkleize(roots, limit=limit), len(roots))


def container_root(*field_roots):
    return merkleize(list(field_roots))


# ------------------------------------------------------- value helpers ----

def pattern(seed, n):
    """Deterministic filler; mirrored by fixturePattern in the Go tests."""
    return bytes((seed * 37 + i * 11 + (i // 256) * 3) % 256 for i in range(n))


def decode_bytes(s, n):
    if s.startswith("pattern:"):
        return pattern(int(s[len("pattern:"):]), n)
    assert s.startswith("0x")
    b = bytes.fromhex(s[2:])
    assert len(b) == n, (s, n)
    return b


def u64(s):
    v = int(s)
    assert 0 <= v <= U64_MAX
    return v


# ---------------------------------------------------------- containers ----

def htr_checkpoint(v):
    return container_root(uint64_root(u64(v["epoch"])), decode_bytes(v["root"], 32))


def htr_beacon_block_header(v):
    return container_root(
        uint64_root(u64(v["slot"])),
        uint64_root(u64(v["proposer_index"])),
        decode_bytes(v["parent_root"], 32),
        decode_bytes(v["state_root"], 32),
        decode_bytes(v["body_root"], 32),
    )


def htr_attestation_data(v):
    return container_root(
        uint64_root(u64(v["slot"])),
        uint64_root(u64(v["index"])),
        decode_bytes(v["beacon_block_root"], 32),
        htr_checkpoint(v["source"]),
        htr_checkpoint(v["target"]),
    )


def signature_list_root(sigs, limit):
    return composite_list_root([byte_vector_root(decode_bytes(s, SIGNATURE_LEN)) for s in sigs], limit)


def htr_attestation(v):
    raw = bytes.fromhex(v["aggregation_bits"][2:])
    return container_root(
        bitlist_root(raw, MAX_ATTESTATION_SIGNATURES),
        htr_attestation_data(v["data"]),
        signature_list_root(v["signatures"], MAX_ATTESTATION_SIGNATURES),
    )


def htr_aggregate_and_proof(v):
    return container_root(
        uint64_root(u64(v["aggregator_index"])),
        htr_attestation(v["aggregate"]),
        byte_vector_root(decode_bytes(v["selection_proof"], SIGNATURE_LEN)),
    )


def htr_voluntary_exit(v):
    return container_root(uint64_root(u64(v["epoch"])), uint64_root(u64(v["validator_index"])))


def htr_sync_selection_data(v):
    return container_root(uint64_root(u64(v["slot"])), uint64_root(u64(v["subcommittee_index"])))


def htr_contribution(v):
    raw = bytes.fromhex(v["aggregation_bits"][2:])
    return container_root(
        uint64_root(u64(v["slot"])),
        decode_bytes(v["beacon_block_root"], 32),
        uint64_root(u64(v["subcommittee_index"])),
        bitvector_root(raw, len(raw) * 8),
        signature_list_root(v["signatures"], MAX_CONTRIBUTION_SIGNATURES),
    )


def htr_contribution_and_proof(v):
    return container_root(
        uint64_root(u64(v["aggregator_index"])),
        htr_contribution(v["contribution"]),
        byte_vector_root(decode_bytes(v["selection_proof"], SIGNATURE_LEN)),
    )


def htr_registration(v):
    return container_root(
        byte_vector_root(decode_bytes(v["fee_recipient"], ADDRESS_LEN)),
        uint64_root(u64(v["gas_limit"])),
        uint64_root(u64(v["timestamp"])),
        byte_vector_root(decode_bytes(v["pubkey"], PUBKEY_LEN)),
    )


def htr_uint64(v):
    return uint64_root(u64(v))


def htr_bytes32(v):
    return decode_bytes(v, 32)


HTR = {
    "BeaconBlockHeader": htr_beacon_block_header,
    "Checkpoint": htr_checkpoint,
    "AttestationData": htr_attestation_data,
    "Attestation": htr_attestation,
    "AggregateAttestationAndProof": htr_aggregate_and_proof,
    "VoluntaryExit": htr_voluntary_exit,
    "SyncAggregatorSelectionData": htr_sync_selection_data,
    "SyncCommitteeContribution": htr_contribution,
    "ContributionAndProof": htr_contribution_and_proof,
    "ValidatorRegistrationV1": htr_registration,
    "Uint64": htr_uint64,
    "Bytes32": htr_bytes32,
}

Z32 = "0x" + "00" * 32
F32 = "0x" + "ff" * 32
MAX = str(U64_MAX)

ZERO_DATA = {"slot": "0", "index": "0", "beacon_block_root": Z32,
             "source": {"epoch": "0", "root": Z32}, "target": {"epoch": "0", "root": Z32}}
DATA = {"slot": "1234", "index": "3", "beacon_block_root": "pattern:5",
        "source": {"epoch": "8", "root": "pattern:6"}, "target": {"epoch": "9", "root": "pattern:7"}}
MAX_DATA = {"slot": MAX, "index": MAX, "beacon_block_root": F32,
            "source": {"epoch": MAX, "root": F32}, "target": {"epoch": MAX, "root": F32}}


def sigs(first, count):
    return ["pattern:%d" % (first + i) for i in range(count)]


ATT_4 = {"aggregation_bits": "0x1f", "data": DATA, "signatures": sigs(100, 4)}

CASES = [
    ("BeaconBlockHeader", "zero", {"slot": "0", "proposer_index": "0", "parent_root": Z32,
                                   "state_root": Z32, "body_root": Z32}),
    ("BeaconBlockHeader", "typical", {"slot": "1234", "proposer_index": "42", "parent_root": "pattern:1",
                                      "state_root": "pattern:2", "body_root": "pattern:3"}),
    ("BeaconBlockHeader", "max", {"slot": MAX, "proposer_index": MAX, "parent_root": F32,
                                  "state_root": F32, "body_root": F32}),
    ("Checkpoint", "zero", {"epoch": "0", "root": Z32}),
    ("Checkpoint", "typical", {"epoch": "9", "root": "pattern:7"}),
    ("AttestationData", "zero", ZERO_DATA),
    ("AttestationData", "typical", DATA),
    ("AttestationData", "max", MAX_DATA),
    ("Attestation", "empty_bitlist_no_signatures", {"aggregation_bits": "0x01", "data": ZERO_DATA,
                                                    "signatures": []}),
    ("Attestation", "four_bits_one_set", {"aggregation_bits": "0x14", "data": DATA, "signatures": sigs(10, 1)}),
    ("Attestation", "four_of_four", ATT_4),
    ("Attestation", "31_bits_31_signatures", {"aggregation_bits": "0xffffffff", "data": DATA,
                                              "signatures": sigs(20, 31)}),
    ("Attestation", "32_bits_5_bytes_32_signatures", {"aggregation_bits": "0xffffffff01", "data": MAX_DATA,
                                                      "signatures": sigs(60, 32)}),
    ("AggregateAttestationAndProof", "empty", {"aggregator_index": "0",
                                               "aggregate": {"aggregation_bits": "0x01", "data": ZERO_DATA,
                                                             "signatures": []},
                                               "selection_proof": "0x" + "00" * SIGNATURE_LEN}),
    ("AggregateAttestationAndProof", "typical", {"aggregator_index": "17", "aggregate": ATT_4,
                                                 "selection_proof": "pattern:200"}),
    ("VoluntaryExit", "zero", {"epoch": "0", "validator_index": "0"}),
    ("VoluntaryExit", "typical", {"epoch": "100", "validator_index": "42"}),
    ("VoluntaryExit", "max", {"epoch": MAX, "validator_index": MAX}),
    ("SyncAggregatorSelectionData", "zero", {"slot": "0", "subcommittee_index": "0"}),
    ("SyncAggregatorSelectionData", "typical", {"slot": "1234", "subcommittee_index": "0"}),
    ("SyncCommitteeContribution", "minimal_two_bits", {"slot": "1234", "beacon_block_root": "pattern:8",
                                                       "subcommittee_index": "0", "aggregation_bits": "0x0500",
                                                       "signatures": sigs(30, 2)}),
    ("SyncCommitteeContribution", "mainnet_two_bits", {"slot": "1234", "beacon_block_root": "pattern:8",
                                                       "subcommittee_index": "0",
                                                       "aggregation_bits": "0x0500" + "00" * 14,
                                                       "signatures": sigs(30, 2)}),
    ("SyncCommitteeContribution", "minimal_single_bit", {"slot": "7", "beacon_block_root": "pattern:9",
                                                         "subcommittee_index": "0", "aggregation_bits": "0x0080",
                                                         "signatures": sigs(40, 1)}),
    ("SyncCommitteeContribution", "minimal_all_bits", {"slot": "8", "beacon_block_root": "pattern:9",
                                                       "subcommittee_index": "0", "aggregation_bits": "0xffff",
                                                       "signatures": sigs(40, 16)}),
    ("SyncCommitteeContribution", "mainnet_all_bits", {"slot": MAX, "beacon_block_root": F32,
                                                       "subcommittee_index": MAX,
                                                       "aggregation_bits": "0x" + "ff" * 16,
                                                       "signatures": sigs(1, 128)}),
    ("SyncCommitteeContribution", "mainnet_no_bits", {"slot": "0", "beacon_block_root": Z32,
                                                      "subcommittee_index": "0",
                                                      "aggregation_bits": "0x" + "00" * 16, "signatures": []}),
    ("ContributionAndProof", "typical", {"aggregator_index": "42", "selection_proof": "pattern:201",
                                         "contribution": {"slot": "1234", "beacon_block_root": "pattern:8",
                                                          "subcommittee_index": "0", "aggregation_bits": "0x0500",
                                                          "signatures": sigs(30, 2)}}),
    ("ValidatorRegistrationV1", "zero", {"fee_recipient": "0x" + "00" * ADDRESS_LEN, "gas_limit": "0",
                                         "timestamp": "0", "pubkey": "0x" + "00" * PUBKEY_LEN}),
    ("ValidatorRegistrationV1", "typical", {"fee_recipient": "pattern:11", "gas_limit": "30000000",
                                            "timestamp": "1760000000", "pubkey": "pattern:12"}),
    ("Uint64", "zero", "0"),
    ("Uint64", "slot_1234", "1234"),
    ("Uint64", "max", MAX),
    ("Bytes32", "zero", Z32),
    ("Bytes32", "pattern", "pattern:13"),
]


# ------------------------------------------------------- signing roots ----

DOMAINS = {
    "BLOCK_V2": ("00000000", "slot"),
    "ATTESTATION": ("01000000", "epoch"),
    "VOLUNTARY_EXIT": ("04000000", "epoch"),
    "AGGREGATION_SLOT": ("05000000", "slot"),
    "AGGREGATE_AND_PROOF": ("06000000", "slot"),
    "SYNC_COMMITTEE_MESSAGE": ("07000000", "slot"),
    "SYNC_COMMITTEE_SELECTION_PROOF": ("08000000", "slot"),
    "SYNC_COMMITTEE_CONTRIBUTION_AND_PROOF": ("09000000", "slot"),
    "VALIDATOR_REGISTRATION": ("00000001", "genesis"),
}


def compute_fork_data_root(version, gvr):
    return container_root(version + b"\x00" * 28, gvr)


def compute_domain(domain_type, version, gvr):
    return domain_type + compute_fork_data_root(version, gvr)[:28]


def compute_signing_root(object_root, domain):
    return container_root(object_root, domain)


NETWORKS = {
    "mainnet": {"genesis_fork_version": "0x00000000", "slots_per_epoch": 128},
    "minimal": {"genesis_fork_version": "0x00000001", "slots_per_epoch": 8},
    "e2e": {"genesis_fork_version": "0x000000fd", "slots_per_epoch": 6},
}


def signing_case(name, network, fork, artifact, at, object_root):
    gfv = bytes.fromhex(network["genesis_fork_version"][2:])
    gvr = bytes.fromhex(network["genesis_validators_root"][2:])
    dtype, rule = DOMAINS[artifact]
    dtype = bytes.fromhex(dtype)
    if rule == "genesis":
        epoch = None
        domain = compute_domain(dtype, gfv, b"\x00" * 32)
    else:
        epoch = at // network["slots_per_epoch"] if rule == "slot" else at
        prev = bytes.fromhex(fork["previous_version"][2:])
        cur = bytes.fromhex(fork["current_version"][2:])
        version = prev if epoch < int(fork["epoch"]) else cur
        domain = compute_domain(dtype, version, gvr)
    obj = decode_bytes(object_root, 32)
    return {
        "name": name,
        "network": dict(network, slots_per_epoch=str(network["slots_per_epoch"])),
        "fork": fork,
        "type": artifact,
        "at": str(at),
        "object_root": "0x" + obj.hex(),
        "epoch": None if epoch is None else str(epoch),
        "domain": "0x" + domain.hex(),
        "signing_root": "0x" + compute_signing_root(obj, domain).hex(),
    }


def signing_cases():
    out = []
    ats = {"BLOCK_V2": 1234, "ATTESTATION": 205, "VOLUNTARY_EXIT": 100, "AGGREGATION_SLOT": 1234,
           "AGGREGATE_AND_PROOF": 1233, "SYNC_COMMITTEE_MESSAGE": 1235, "SYNC_COMMITTEE_SELECTION_PROOF": 1236,
           "SYNC_COMMITTEE_CONTRIBUTION_AND_PROOF": 1237, "VALIDATOR_REGISTRATION": 1760000000}
    for seed, (net_name, net) in enumerate(sorted(NETWORKS.items())):
        network = dict(net, genesis_validators_root="0x" + pattern(50 + seed, 32).hex())
        gfv = network["genesis_fork_version"]
        fork = {"previous_version": gfv, "current_version": gfv, "epoch": "0"}
        for i, artifact in enumerate(sorted(DOMAINS)):
            out.append(signing_case("%s/%s" % (net_name, artifact), network, fork, artifact, ats[artifact],
                                    "pattern:%d" % (60 + i)))
    # A two-version schedule exercises get_domain's fork selection: epoch 10
    # switches from 0x000000fd to 0x010000fd; e2e has 6 slots per epoch.
    network = dict(NETWORKS["e2e"], genesis_validators_root="0x" + pattern(70, 32).hex())
    fork = {"previous_version": "0x000000fd", "current_version": "0x010000fd", "epoch": "10"}
    for artifact, at in [("BLOCK_V2", 59), ("BLOCK_V2", 60), ("ATTESTATION", 9), ("ATTESTATION", 10),
                         ("VOLUNTARY_EXIT", 9), ("VOLUNTARY_EXIT", U64_MAX),
                         ("SYNC_COMMITTEE_CONTRIBUTION_AND_PROOF", 59),
                         ("SYNC_COMMITTEE_CONTRIBUTION_AND_PROOF", 60), ("VALIDATOR_REGISTRATION", 60)]:
        out.append(signing_case("fork_schedule/%s/%d" % (artifact, at), network, fork, artifact, at,
                                "pattern:80"))
    return out


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    header = {
        "description": "Hand-derived by gen_fixtures.py, an independent Python implementation of the CC0 "
                       "Ethereum consensus specs v1.5.0 with QRL sizes. 'pattern:<seed>' values expand to "
                       "bytes (seed*37 + i*11 + (i//256)*3) mod 256 of the field's length.",
    }
    containers = dict(header, cases=[
        {"type": t, "name": n, "value": v, "root": "0x" + HTR[t](v).hex()} for t, n, v in CASES
    ])
    signing = dict(header, cases=signing_cases())
    for name, doc in [("containers.json", containers), ("signing.json", signing)]:
        with open(os.path.join(here, name), "w") as f:
            json.dump(doc, f, indent=1, sort_keys=False)
            f.write("\n")


if __name__ == "__main__":
    main()

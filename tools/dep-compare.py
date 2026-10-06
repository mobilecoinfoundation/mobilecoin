#!/usr/bin/env python3

from collections import defaultdict
import tomllib

# Given a Cargo.lock path, map each package name and source to its versions.
# Source is part of the identity because enclave workspaces intentionally patch
# some crates (notably cpufeatures) to SGX-safe forks.
def load_cargo_lock_packages(path):
    with open(path, "rb") as handle:
        lock = tomllib.load(handle)
    result = defaultdict(set)
    for package in lock['package']:
        key = (package['name'], package.get('source'))
        result[key].add(package['version'])
    return result

root = load_cargo_lock_packages("Cargo.lock")
consensus = load_cargo_lock_packages("consensus/enclave/trusted/Cargo.lock")
fog_ingest = load_cargo_lock_packages("fog/ingest/enclave/trusted/Cargo.lock")
fog_ledger = load_cargo_lock_packages("fog/ledger/enclave/trusted/Cargo.lock")
fog_view = load_cargo_lock_packages("fog/view/enclave/trusted/Cargo.lock")

# Display whenever things differ from the root cargo lock
for (name, source), versions in root.items():
    key = (name, source)
    if key in consensus and not versions.issuperset(consensus[key]):
        print(f"{name}: root = {versions}, consensus = {consensus[key]}")
    if key in fog_ingest and not versions.issuperset(fog_ingest[key]):
        print(f"{name}: root = {versions}, fog_ingest = {fog_ingest[key]}")
    if key in fog_ledger and not versions.issuperset(fog_ledger[key]):
        print(f"{name}: root = {versions}, fog_ledger = {fog_ledger[key]}")
    if key in fog_view and not versions.issuperset(fog_view[key]):
        print(f"{name}: root = {versions}, fog_view = {fog_view[key]}")

#!/usr/bin/env python3

import toml
from collections import defaultdict

# Given a Cargo.lock path, get a dictionary mapping package names to all version numbers for that package
def load_cargo_lock_packages(path):
    lock = toml.load(path)
    result = defaultdict(set)
    for package in lock['package']:
        result[package['name']].add(package['version'])
    return result

root = load_cargo_lock_packages("Cargo.lock")
consensus = load_cargo_lock_packages("consensus/enclave/trusted/Cargo.lock")
fog_ingest = load_cargo_lock_packages("fog/ingest/enclave/trusted/Cargo.lock")
fog_ledger = load_cargo_lock_packages("fog/ledger/enclave/trusted/Cargo.lock")
fog_view = load_cargo_lock_packages("fog/view/enclave/trusted/Cargo.lock")

# Display whenever things differ from the root cargo lock
for name, versions in root.items():
    if name in consensus and not versions.issuperset(consensus[name]):
        print(f"{name}: root = {versions}, consensus = {consensus[name]}")
    if name in fog_ingest and not versions.issuperset(fog_ingest[name]):
        print(f"{name}: root = {versions}, fog_ingest = {fog_ingest[name]}")
    if name in fog_ledger and not versions.issuperset(fog_ledger[name]):
        print(f"{name}: root = {versions}, fog_ledger = {fog_ledger[name]}")
    if name in fog_view and not versions.issuperset(fog_view[name]):
        print(f"{name}: root = {versions}, fog_view = {fog_view[name]}")

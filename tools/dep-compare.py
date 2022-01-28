#!/usr/bin/env python3

import toml

# Given a Cargo.lock path, get a dictionary mapping package names to version numbers
def load_cargo_lock_packages(path):
    lock = toml.load(path)
    return {package['name']: package['version'] for package in lock['package']}

root = load_cargo_lock_packages("Cargo.lock")
consensus = load_cargo_lock_packages("consensus/enclave/trusted/Cargo.lock")
fog_ingest = load_cargo_lock_packages("fog/ingest/enclave/trusted/Cargo.lock")
fog_ledger = load_cargo_lock_packages("fog/ledger/enclave/trusted/Cargo.lock")
fog_view = load_cargo_lock_packages("fog/view/enclave/trusted/Cargo.lock")

# Display whenever things differ from the root cargo lock
for name, version in root.items():
    if name in consensus and consensus[name] != version:
        print(f"{name}: root = {version}, consensus = {consensus[name]}")
    if name in fog_ingest and fog_ingest[name] != version:
        print(f"{name}: root = {version}, fog_ingest = {fog_ingest[name]}")
    if name in fog_ledger and fog_ledger[name] != version:
        print(f"{name}: root = {version}, fog_ledger = {fog_ledger[name]}")
    if name in fog_view and fog_view[name] != version:
        print(f"{name}: root = {version}, fog_view = {fog_view[name]}")

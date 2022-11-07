# Mobilecoin Internal CI/CD tools

These build, dockerfiles, helm charts and scripts are used internally for MobileCoin builds and deployments and is subject to change without notice, YMMV, no warranties provided, all that good stuff.

## Artifacts

This process will create a set of versioned docker containers and helm charts for deploying the release.

- Containers - https://hub.docker.com/u/mobilecoin
- Helm Chart Repo URL - https://s3.us-east-2.amazonaws.com/charts.mobilecoin.com/

### Versioning

We use [Semver 2](https://semver.org/) for general versioning.

⚠️ Note: Because we have multiple final releases (TestNet, MainNet...), and semver metadata isn't taken in account for ordering, all of the releases are technically "development" releases. Be aware that some tools like `helm` will need extra flags to display development versions.

**Feature Branches**

- `feature/my-awesome-feature` valid characters `[a-z][0-9]-`
- Feature branch names will be normalized for versioning, namespaces, dns...
  - `feature/` prefix will be removed
  - namespaces will be prefixed with `mc-`
  - semver portion will be set to `v0`.

format:
```
v0-${branch}.${GITHUB_RUN_NUMBER}.sha-${sha}
```

examples:
```
feature/my.awesome_feature

v0.0.0-my-awesome-feature.21.sha-abcd1234
```

**Release branches**

- `release/v2` valid characters `v[0-9]+`
- Release branches will be normalized for versioning, namespaces, dns...
  - namespaces will be prefixed with `mc-`
  - semver portion will be set to `v0`.

format:
```
v0-${GITHUB_RUN_NUMBER}.sha-${sha}
```

examples:
```
release/v2

v0-21.sha-abcd1234
```

**Tags**

- `v2.0.0` valid characters `v[0-9]+\.[0-9]+\.[0-9]+`
- Tags will be normalized for versioning, namespaces, dns...
  - namespaces will be prefixed with `mc-`
  - semver will be set to match the branch name.
  - tags will create a `v{tag}-dev` release for use in static environments

format:
```
v2.0.0-${GITHUB_RUN_NUMBER}.sha-${sha}
v2.0.0-dev
```

## CI triggers

This workflow is set up to trigger of certain branch patterns.

### Branches - `feature/*, release/*, master`

Branches will trigger a build that will create a dynamic development environment and run integration tests against the environment.

| Tags | SGX_MODE | IAS_MODE | Signer | Description |
| --- | --- | --- | --- | --- |
| `v0.0.0-my-awesome-feature.21.sha-abcd1234` | `HW` | `DEV` | CI Signed Development | For use in development environments. |

### Semver tags - `v2.0.0`

Tags will trigger a build that will create a set of release artifacts.

TBD: Automatically deploy/destroy this release to the development cluster.

| Tags | SGX_MODE | IAS_MODE | Signer | Description |
| --- | --- | --- | --- | --- |
| `v2.0.0-dev` | `HW` | `DEV` | CI Signed Development | For use in development environments. |


## CI Commit Message Flags

This workflow watches the head(latest) commit for the current push and parses the commit message for defined bracket `[]` statements.

### `[tag=]` Flag

The `[tag=]` flag will override the automatically generated docker/helm tag and deploy the specified version in the `current-release-*` steps.

### `[skip *]` Flags

⚠️ Using skip flags may lead to incomplete and/or broken builds.

Available skips:

- `[skip ci]` - GHA built-in to skip all workflow steps.
- `[skip build]` - Skip rust/go builds.
- `[skip docker]` - Skip docker image build/publish.
- `[skip charts]` - Skip helm chart build/publish.
- `[skip deploy-v1-bv0-release]` - Skip deploy of v1 at block_version 0
- `[skip test-v1-bv0-release]` - Skip test of v1 at block_version 0
- `[skip deploy-v2-bv0-release]` - Skip deploy of v2 at block_version 0
- `[skip test-v2-bv0-release]` - Skip test of v2 at block_version 0
- `[skip update-v2-to-bv2-release]` - Skip update of v2 at block_version 2
- `[skip test-v2-bv2-release]` - Skip test of v2 at block_version 2
- `[skip deploy-current-bv2-release]` - Skip deploy of current at block_version 2
- `[skip test-current-bv2-release]` - Skip test of current at block_version 2
- `[skip update-current-to-bv3]` - Skip update of current at block_version 3
- `[skip test-current-bv3-release]` - Skip test of current at block_version 3

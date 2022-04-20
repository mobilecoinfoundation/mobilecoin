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
  - semver portion will be set to `v0.0.0`.

format:
```
v0.0.0-${branch}.${GITHUB_RUN_NUMBER}.sha-${sha}
```

examples:
```
feature/my.awesome_feature

v0.0.0-my-awesome-feature.21.sha-abcd1234
```

**Release branches**

- `release/v1.2.0` valid characters `v[0-9]+/.[0-9]+/.[0-9]+`
- Release branches will be normalized for versioning, namespaces, dns...
  - namespaces will be prefixed with `release-`
  - semver will be set to match the branch name.
  - `-dev` and full tags will be create for the artifacts.

format:
```
v1.2.3-${GITHUB_RUN_NUMBER}.sha-${sha}
v1.2.3-dev
```

examples:
```
release/v1.2.3

v1.2.3-21.sha-abcd1234
v1.2.3-dev
```

## CI triggers

This workflow is set up to trigger of certain branch patterns.

### Feature Branches - `feature/*`

Feature branches will trigger a build that will create a dynamic development environment and run integration tests against the environment.

| Tags | SGX_MODE | IAS_MODE | Signer | Description |
| --- | --- | --- | --- | --- |
| `v0.0.0-my-awesome-feature.21.sha-abcd1234` | `HW` | `DEV` | CI Signed Development | For use in development environments. |

### Release Branches - `release/*`

Release branches will trigger a build that will create a set of release artifacts.

TBD: Automatically deploy/destroy this release to the development cluster.

| Tags | SGX_MODE | IAS_MODE | Signer | Description |
| --- | --- | --- | --- | --- |
| `v1.0.0-dev` | `HW` | `DEV` | CI Signed Development | For use in development environments. |

### Production Releases - Manual Trigger

⚠️ **Not Yet Implemented**

Once the release branch is tested you can use the manual `workflow-dispatch` actions to build the TestNet and MainNet deployment artifacts. This process will expect a set of externally built signed enclaves uploaded to S3 storage.

| Tags | SGX_MODE | IAS_MODE | Signer | Description |
| --- | --- | --- | --- | --- |
| `v1.0.0-test` | `HW` | `PROD` | External Signed TestNet | TestNet Build. |
| `v1.0.0-prod` | `HW` | `PROD` | External Signed MainNet | MainNet Build. |

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
- `[skip dev-reset]` - Skip dev namespace reset.
- `[skip previous-deploy]` - Skip deploy of the previous consensus/fog release.
- `[skip previous-test]` - Skip test of previous release.
- `[skip current-release-v0-deploy]` - Skip current release at block-version=0 deploy.
- `[skip current-release-v0-test]`- Skip current release at block-version=0 deploy.
- `[skip current-release-v1-update]` - Skip current release at block-version=1 consensus update.
- `[skip current-release-v1-test]` - Skip current release at block-version=1 tests.

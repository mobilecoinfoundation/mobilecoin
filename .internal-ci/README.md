# Mobilecoin Internal CI/CD tools

These build, dockerfiles, helm charts and scripts are used internally for MobileCoin builds and deployments and is subject to change without notice, YMMV, no warranties provided, all that good stuff.

## Workflow

- Members of the `mobilecoinfoundation` org should use the Branching Workflow.
- External contributors should follow the Forking Workflow.

### Branching Workflow

**General updates (feature and fixes)**

For general updates cut a `feature/*` off of the `develop` branch and push changes to the `feature/*` branch. Pushing changes to `origin feature/*` will trigger `mobilecoin-dev-cd` GitHub Actions workflow and deploy a dynamic development instance and run integration tests. See the `👾 Environment Info 👾` job included in the workflow for dynamic development deployment details.

**Releases**

Release are versioned using [Semver 2](https://semver.org/).

- Major - Breaking changes, increment the first digit.
- Minor - Enclave updates and features, increment the second digit.
- Patch - Non-Enclave updates and fixes should follow the "Patch" release process.

Cut a `release/v0.0.0` style branch off of `develop`. Pushing changes to `origin release/v*.*.*` will create a `release-v*-*-*` dynamic deployment to the development cluster for testing. The branch will also publish container images and helm charts tagged with `v*.*.*-dev`. Binaries in these artifacts will be singed with development keys.

Promote a release by submitting a PR to merge code into `main`.

Tag and create a GitHub Release for the git commit on `main`.

Merge `main` back into `develop` for a clean history.

**Patch**

A Patch release is for non-enclave changes to be applied between Major or Minor (enclave) releases. Create a `release/v*.*.*`  cut off the latest tag in `main`.

Follow the same testing/deployment process described in above in Releases.

### Branch Reference

- `main` is consistent with the latest release.
- `develop` (default) is the edge branch and would be the PR/merge target between releases.
  - automatically built and deployed to `develop` namespace.
  - GHA cache will share cache targets from the default branch with other branches, (`feature`, `release`...)
- `feature/*` target branch pattern for integration into our repo and ci/testing workflows.
  - automatically built and deployed to the develop cluster on push.
  - dev deploy is automatically torn down when branch is removed.
  - branches are removed once pr is merged into `develop`
  - Outside forks would be reviewed and then merged into a feature branch for deployment and testing before merge into `develop`
- `release/0.0.0` semver release branches
  - cut from `develop` and/or cherry-picked features.
    - for Hotfix, cut from `main` and add features.
  - automatically builds `v0.0.0-dev` releases
  - can target with manual (push button) build for TestNet/MainNet and other stable environments.  Will expect an external signed enclave `v0.0.0-test, v0.0.0-prod`.
  - Merged into `main` and back into `develop` on successful release.
  - `main` should be tagged and a release cut.

### Fork Workflow

External contributors may create a fork of this repo and create potential changes to be incorporated into MobileCoin core applications. See [CONTRIBUTING](/CONTRIBUTING.md) for more details.

Users should create a branch in their fork cut from the `develop` branch and submit PRs to the upstream `develop` branch.

A member of `mobilecoinfoundation` will review the PR and if accepted will create a `feature/*` branch to merge the changes into for CI and Integration testing.

**Member Notes**

⚠️ External PRs must not be merged directly into `develop`, `release` or `main` branches. ⚠️

All PRs from external forks must be reviewed and then pushed into a `feature/*` branch.

It is important to review all external changes with an eye toward security. Special care should be taken with any modifications to `.internal-ci` and `.github` directories.

## Artifacts

This process will create a set of versioned docker containers and helm charts for deploying the release.

- Containers - https://hub.docker.com/mobilecoin
- Charts - https://s3.us-east-2.amazonaws.com/charts.mobilecoin.com/

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

- `release/v1.2.0` valid characters `v[0-9].`
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

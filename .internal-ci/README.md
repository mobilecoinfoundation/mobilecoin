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

This workflow is set up to trigger off certain branch patterns.

*NOTE:* The branch must contain some change to a source-code file for the CI to be triggered (i.e. branching off `main` to create a feature branch environment without any changes will not trigger CI)

### Branches - `feature/*, release/*, main`

Branches will trigger a build that will create a dynamic development environment and run integration tests against the environment.

| Tags | SGX_MODE | Signer | Description |
| --- | --- | --- | --- |
| `v0.0.0-my-awesome-feature.21.sha-abcd1234` | `HW` | CI Signed Development | For use in development environments. |

### Semver tags - `v2.0.0`

Tags will trigger a build that will create a set of release artifacts.

TBD: Automatically deploy/destroy this release to the development cluster.

| Tags | SGX_MODE | Signer | Description |
| --- | --- | --- | --- |
| `v2.0.0-dev` | `HW` | CI Signed Development | For use in development environments. |

### Deployment Status & Environment Info

 * Inspect the `Actions` tab for the workflow for your branchname to monitor for completion/success
 * From the `Jobs` list, select `Environment Info`, and expand `Print Environment Details` for the deployed Environment Information
 * The environment lifetime is tied to the branch lifetime, and will be torn down when the branch is deleted

## CI Commit Message Flags

This workflow watches the head(latest) commit for the current push and parses the commit message for defined bracket `[]` statements.

### `[tag=]` Flag

The `[tag=]` flag will override the automatically generated docker/helm tag and deploy the specified version in the `current-release-*` steps.

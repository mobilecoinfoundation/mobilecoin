# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

The crates in this repository do not adhere to [Semantic Versioning](https://semver.org/spec/v2.0.0.html) at this time.

## [6.0.0]

### Added

- Add `payment_id` to `PaymentRequest` protobuf ([#3341])
- Add zeroize on drop to core account types ([#3402])
- Add light client verifier ([#3390], [#3399], [#3397], [#3411], [#3412], [#3401])
- Add light client relayer ([#3400])
- Add RTH memos to mobilecoind ([#3945])

#### CI/CD

- Add "Deploy Fog" manual actions ([#3642], [#3611], [#3599])
- Add GHA job to save ledger/watcher DB files to azure blob storage ([#3349])
- Add a download step to the ledger refresh ([#3372])
- Add rust version to workspace for enclaves ([#3700])
- Make minimum number of signatures for ledger bootstrap variable ([#3946])
- Bump go version in CD to 1.22.2 [(#3958)]

### Fixed

- Fix an error code returned by mobilecoind for bad b58 address ([#3657])
- Fix fog ingest load test ([#3394])
- Fix incremental builds always rebuilding on the second run ([#3808])
- Fix intermittent incremental build failures, move sim certificates to build
  directory ([#3807])
- Fix optimization tx's when using nonzero token ids ([#3817])
- Fix fog-view load test to report more useful metrics and actually work ([#3357])
- Missing punctuation in README ([#3815])
- Update refresh-ledger-bootstrap and dispatch-dev-testnet-fog workflows for
  smaller testnet ([#3944])
- Fix fog ledger shards needing to load all blocks ([#3923], [#3933])

#### CI/CD

- Fix intermittent Postgres failures by using postgres service in GH actions ([#3785])

### Security

- Update Intel SGX SDK to 2.23.100.2 ([#3617], [#3618], [#3777], [#3957])

### Changed

- Bump ISV SVN for enclaves ([#3855])
- The enclaves now use DCAP attestation. Clients now need to pass a vec of
  `TrustedIdentity` instead of a verifier. This allows clients to consume this
  version of the code and attest with both the legacy EPID enclaves and the
  newer DCAP enclaves. ([#3482], [#3603], [#3514], [#3497], [#3504], [#3516],
  [#3577], [#3573], [#3572], [#3554], [#3537], [#3377], [#3588], [#3569],
  [#3565], [#3509], [#3510], [#3610], [#3481], [#3485], [#3575], [#3524],
  [#3508], [#3586], [#3375], [#3480], [#3583], [#3496], [#3566], [#3369],
  [#3521], [#3749], [#3790], [#3612], [#3605], [#3593], [#3570], [#3568],
  [#3579], [#3495], [#3615], [#3616], [#3614], [#3561], [#3395], [#3602],
  [#3436], [#3634], [#3580], [#3503], [#3589], [#3613], [#3608], [#3438],
  [#3439], [#3440], [#3441], [#3523], [#3735], [#3445], [#3444], [#3442],
  [#3434], [#3443], [#3435], [#3449], [#3421], [#3620], [#3607], [#3585],
  [#3454], [#3592], [#3856])
- Rename primary development branch from `master` branch to `main` ([#3633])
- Limit `cargo sort` in `tools/lint.sh` to only modify incorrect files. ([#3595])
- Update lint script to lint root workspace once ([#3501])
- Move the enclaves into the same build directory, reducing overall compilation
  time ([#3775])
- Reduce the static startup memory of enclaves ([#3719])
- Remove "-D warnings" for development builds ([#3500])
- Remove newlines from enclave panic message ([#3770])

#### CI/CD

- Remove 4 core restriction on CI builds ([#3798])
- Remove nodejs from docker image ([#3627])
- Remove fog local network test ([#3799])
- Update ledger bootstrap to 5.0.8 ([#3371], [#3373], [#3600])
- Use gha-runner-scale-sets ([#3849])

#### Github Actions

- Bump actions/checkout from 3 to 4 ([#3531], [#3705])
- Bump actions/download-artifact from 3 to 4 ([#3806])
- Bump actions/setup-go from 4 to 5 ([#3778])
- Bump actions/setup-node from 3 to 4 ([#3648])
- Bump actions/setup-python from 4 to 5 ([#3779])
- Bump docker/build-push-action from 4 to 5 ([#3548])
- Bump docker/login-action from 2 to 3 ([#3552])
- Bump docker/metadata-action from 4 to 5 ([#3547])
- Bump docker/setup-buildx-action from 2 to 3 ([#3553])

#### Go Dependencies

- Bump go grpc gateway ([#3955])

#### Python Dependencies

- Bump flask from 1.1.2 to 2.3.2 ([#3343], [#3344])
- Bump jinja2 from 2.11.3 to 3.1.3 ([#3851])
- Bump grpcio from 1.32.0 to 1.53.2 ([#3403], [#3404], [#3405], [#3406],
  [#3905], [#3906], [#3904])
- Bump requests from 2.27.1 to 2.31.0 ([#3359])
- Bump urllib3 from 1.26.8 to 1.26.18 ([#3624], [#3598])
- Bump werkzeug from 2.2.3 to 3.0.1 ([#3654])

#### Rust Dependencies

- Update rust toolchain to `nightly-2023-10-01` ([#3621], [#3623], [#3635],
  [#3622], [#3619], [#3626], [#3628])
- Bump x25519-dalek, curve25519-dalek and ed25519-dalek ([#3544], [#3898], [#3894])
- Bump aead from 0.5.1 to 0.5.2 ([#3416])
- Bump aes from 0.8.2 to 0.8.4 ([#3426], [#3909])
- Bump aes-gcm from 0.10.1 to 0.10.2 ([#3415], [#3576])
- Bump anyhow from 1.0.69 to 1.0.80 ([#3498], [#3507], [#3539], [#3828], [#3920])
- Bump assert_cmd from 2.0.10 to 2.0.14 ([#3356], [#3499], [#3853], [#3924])
- Bump async-channel from 1.7.1 to 2.2.0 ([#3804], [#3902])
- Bump backtrace from 0.3.67 to 0.3.69 ([#3647])
- Bump base64 from 0.21.0 to 0.21.7 ([#3483], [#3650], [#3845], [#3852])
- Bump bitflags from 2.3.3 to 2.4.2 ([#3644], [#3867])
- Bump cargo_metadata from 0.15.3 to 0.18.1 ([#3528], [#3564], [#3652])
- Bump cc from 1.0.79 to 1.0.88 ([#3515], [#3679], [#3716], [#3907], [#3921],
  [#3928], [#3930])
- Bump certifi from 2022.12.7 to 2023.7.22 in /mobilecoind/strategies ([#3453])
- Bump chrono from 0.4.24 to 0.4.34 ([#3493], [#3546], [#3653], [#3875],
  [#3882], [#3908])
- Bump clap from 4.1.11 to 4.5.1 ([#3325], [#3462], [#3591], [#3762], [#3826],
  [#3831], [#3847], [#3658], [#3709], [#3751], [#3854], [#3864], [#3866],
  [#3901], [#3914])
- Bump clio from 0.3.4 to 0.3.5 ([#3800])
- Bump cookie from 0.17.0 to 0.18.0 ([#3666])
- Bump criterion from 0.4.0 to 0.5.1 ([#3479])
- Bump crossbeam-channel from 0.5.7 to 0.5.12 ([#3466], [#3801], [#3824],
  [#3844], [#3939])
- Bump ctrlc from 3.2.5 to 3.4.2 ([#3447], [#3693], [#3822])
- Bump curve25519-dalek from 4.1.0 to 4.1.1 ([#3667])
- Bump der from 0.7.7 to 0.7.8 ([#3578])
- Bump diesel from 2.1.0 to 2.1.4 ([#3604], [#3683], [#3723])
- Bump diesel-derive-enum from 2.0.1 to 2.1.0 ([#3432])
- Bump diesel_migrations from 2.0.0 to 2.1.0 ([#3455])
- Bump digest from 0.10.6 to 0.10.7 ([#3456])
- Bump dirs from 4.0.0 to 5.0.1 ([#3345])
- Bump displaydoc from 0.2.3 to 0.2.4 ([#3490])
- Bump dyn-clone from 1.0.16 to 1.0.17 ([#3929])
- Bump ed25519 from 2.2.0 to 2.2.3 ([#3347], [#3590], [#3681])
- Bump ed25519-dalek from 2.0.0 to 2.1.0 ([#3726])
- Bump futures from 0.3.28 to 0.3.30 ([#3669], [#3821])
- Bump generic-array from 0.14.6 to 0.14.7 ([#3448])
- Bump getrandom from 0.2.8 to 0.2.12 ([#3324], [#3489], [#3699], [#3842])
- Bump grpcio from 0.12.1 to 0.13.0 ([#3609])
- Bump h2 from 0.3.16 to 0.3.26 ([#3330], [#3919], [#3954])
- Bump hashbrown from 0.13.2 to 0.14.3 ([#3460], [#3640], [#3746])
- Bump heapless from 0.7.16 to 0.8.0 ([#3702])
- Bump hex-literal from 0.3.4 to 0.4.1 ([#3413])
- Bump hkdf from 0.12.3 to 0.12.4 ([#3802])
- Bump itertools from 0.10.5 to 0.12.1 ([#3606], [#3722], [#3887])
- Bump libc from 0.2.140 to 0.2.153 ([#3433], [#3587], [#3682], [#3695],
  [#3791], [#3841], [#3890])
- Bump libz-sys from 1.1.8 to 1.1.15 ([#3467], [#3848], [#3883])
- Bump link-cplusplus from 1.0.8 to 1.0.9 ([#3581])
- Bump log from 0.4.17 to 0.4.21 ([#3505], [#3937])
- Update `mbedtls`, `mbedtls-sys` forks to support apple m1 and android builds
  ([#3823], [#3656])
- Bump mc-sgx-core-sys-types from 0.9.0 to 0.10.0 ([#3768])
- Bump mikepenz/action-junit-report from 3 to 4 ([#3540])
- Bump mockall from 0.11.3 to 0.12.1 ([#3425], [#3793], [#3819], [#3794])
- Bump mio from 0.8.9 to 0.8.11 ([#3942])
- Bump num_cpus from 1.15.0 to 1.16.0 ([#3420])
- Bump once_cell from 1.17.1 to 1.19.0 ([#3450], [#3781])
- Bump opentelemetry from 0.18.0 to 0.21.0 ([#3469], [#3697])
- Bump opentelemetry_sdk from 0.21.0 to 0.21.2 ([#3714], [#3830])
- Bump pem from 2.0.0 to 3.0.3 ([#3459], [#3670], [#3795])
- Bump percent-encoding from 2.2.0 to 2.3.1 ([#3471], [#3741])
- Bump pkg-config from 0.3.26 to 0.3.30 ([#3584], [#3812], [#3869], [#3912])
- Bump predicates from 3.0.1 to 3.1.0 ([#3470], [#3651], [#3863])
- Bump primitive-types from 0.12.1 to 0.12.2 ([#3645])
- Bump proc-macro2 from 1.0.52 to 1.0.78 ([#3326], [#3661], [#3745], [#3836], [#3876])
- Bump proptest from 1.1.0 to 1.4.0 ([#3452], [#3637], [#3710])
- Bump prost from 0.11.8 to 0.12.1 ([#3474], [#3562])
- Bump prost-build from 0.12.1 to 0.12.3 ([#3729], [#3739])
- Bump pygments from 2.7.4 to 2.15.0 in /mobilecoind/strategies ([#3427])
- Bump quote from 1.0.26 to 1.0.33 ([#3446], [#3464], [#3629])
- Bump rand_hc from 0.3.1 to 0.3.2 ([#3465])
- Bump rayon from 1.7.0 to 1.9.0 ([#3680], [#3868], [#3934])
- Bump regex from 1.7.1 to 1.10.3 ([#3487], [#3715], [#3724], [#3878])
- Bump reqwest from 0.11.15 to 0.11.24 ([#3451], [#3601], [#3809], [#3891])
- Bump rocket from 0.5.0-rc.2 to 0.5.0 ([#3488], [#3690], [#3732])
- Bump rustls-webpki from 0.100.1 to 0.100.2 ([#3519])
- Bump semver from 1.0.17 to 1.0.22 ([#3431], [#3646], [#3832], [#3917])
- Bump sentry from 0.30.0 to 0.32.2 ([#3393], [#3597], [#3708], [#3750],
  [#3810], [#3888])
- Bump serde from 1.0.159 to 1.0.197 ([#3327], [#3424], [#3457], [#3476],
  [#3522], [#3543], [#3632], [#3664], [#3698], [#3736], [#3834], [#3835],
  [#3884], [#3922])
- Bump serde_json from 1.0.103 to 1.0.114 ([#3478], [#3527], [#3571], [#3678],
  [#3827], [#3837], [#3885], [#3886], [#3926])
- Bump serde_with from 3.2.0 to 3.4.0 ([#3594], [#3671], [#3877], [#3881],
  [#3889], [#3900])
- Bump serial_test from 1.0.0 to 3.0.0 ([#3419], [#3843])
- Bump sha2 from 0.10.6 to 0.10.8 ([#3477], [#3638], [#3494])
- Bump shlex from 1.0.0 to 1.3.0 ([#3874])
- Bump signal-hook from 0.3.15 to 0.3.17 ([#3418])
- Bump signature from 2.0.0 to 2.1.0 ([#3728])
- Bump siphasher from 0.3.10 to 1.0.0 ([#3567])
- Bump slog-async from 2.7.0 to 2.8.0 ([#3641])
- Bump slog-term from 2.9.0 to 2.9.1 ([#3915])
- Bump syn from 2.0.12 to 2.0.52 ([#3339], [#3473], [#3636], [#3660], [#3694],
  [#3792], [#3796], [#3816], [#3825], [#3833], [#3913], [#3916], [#3932], [#3938])
- Bump tempfile from 3.4.0 to 3.10.0 ([#3353], [#3458], [#3542], [#3672],
  [#3818], [#3931], [#3893])
- Bump textwrap from 0.11.0 to 0.16.1 ([#3665], [#3685], [#3925])
- Bump tokio from 1.25.0 to 1.36.0 ([#3511], [#3513], [#3684], [#3704], [#3783],
  [#3811], [#3892])
- Bump toml from 0.7.3 to 0.8.2 ([#3414], [#3631])
- Bump url from 2.3.1 to 2.5.0 ([#3484], [#3659], [#3744])
- Bump walkdir from 2.3.3 to 2.4.0 ([#3639])
- Bump wasm-bindgen from 0.2.88 to 0.2.90 ([#3743], [#3861])
- Bump wasm-bindgen-test from 0.3.34 to 0.3.41 ([#3461], [#3692], [#3747],
  [#3860], [#3896])
- Bump webpki from 0.22.0 to 0.22.2 ([#3534], [#3596])
- Bump x509-cert from 0.2.3 to 0.2.5 ([#3518], [#3820])
- Bump xml-rs from 0.8.3 to 0.8.14 ([#3381])
- Bump yare from 1.0.2 to 2.0.0 ([#3630])
- Bump zeroize from 1.5.6 to 1.7.0 ([#3506], [#3725], [#3731])

[#3324]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3324
[#3325]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3325
[#3326]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3326
[#3327]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3327
[#3330]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3330
[#3339]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3339
[#3341]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3341
[#3343]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3343
[#3344]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3344
[#3345]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3345
[#3347]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3347
[#3349]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3349
[#3353]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3353
[#3356]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3356
[#3357]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3357
[#3359]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3359
[#3369]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3369
[#3371]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3371
[#3372]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3372
[#3373]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3373
[#3375]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3375
[#3377]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3377
[#3381]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3381
[#3390]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3390
[#3393]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3393
[#3394]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3394
[#3395]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3395
[#3397]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3397
[#3399]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3399
[#3400]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3400
[#3401]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3401
[#3402]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3402
[#3403]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3403
[#3404]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3404
[#3405]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3405
[#3406]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3406
[#3411]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3411
[#3412]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3412
[#3413]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3413
[#3414]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3414
[#3415]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3415
[#3416]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3416
[#3418]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3418
[#3419]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3419
[#3420]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3420
[#3421]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3421
[#3424]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3424
[#3425]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3425
[#3426]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3426
[#3427]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3427
[#3431]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3431
[#3432]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3432
[#3433]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3433
[#3434]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3434
[#3435]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3435
[#3436]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3436
[#3438]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3438
[#3439]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3439
[#3440]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3440
[#3441]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3441
[#3442]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3442
[#3443]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3443
[#3444]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3444
[#3445]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3445
[#3446]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3446
[#3447]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3447
[#3448]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3448
[#3449]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3449
[#3450]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3450
[#3451]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3451
[#3452]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3452
[#3453]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3453
[#3454]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3454
[#3455]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3455
[#3456]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3456
[#3457]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3457
[#3458]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3458
[#3459]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3459
[#3460]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3460
[#3461]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3461
[#3462]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3462
[#3464]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3464
[#3465]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3465
[#3466]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3466
[#3467]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3467
[#3469]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3469
[#3470]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3470
[#3471]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3471
[#3473]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3473
[#3474]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3474
[#3476]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3476
[#3477]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3477
[#3478]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3478
[#3479]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3479
[#3480]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3480
[#3481]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3481
[#3482]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3482
[#3483]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3483
[#3484]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3484
[#3485]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3485
[#3487]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3487
[#3488]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3488
[#3489]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3489
[#3490]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3490
[#3493]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3493
[#3494]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3494
[#3495]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3495
[#3496]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3496
[#3497]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3497
[#3498]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3498
[#3499]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3499
[#3500]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3500
[#3501]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3501
[#3503]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3503
[#3504]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3504
[#3505]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3505
[#3506]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3506
[#3507]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3507
[#3508]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3508
[#3509]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3509
[#3510]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3510
[#3511]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3511
[#3513]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3513
[#3514]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3514
[#3515]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3515
[#3516]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3516
[#3518]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3518
[#3519]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3519
[#3521]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3521
[#3522]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3522
[#3523]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3523
[#3524]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3524
[#3527]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3527
[#3528]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3528
[#3531]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3531
[#3534]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3534
[#3537]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3537
[#3539]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3539
[#3540]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3540
[#3542]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3542
[#3543]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3543
[#3544]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3544
[#3546]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3546
[#3547]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3547
[#3548]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3548
[#3552]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3552
[#3553]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3553
[#3554]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3554
[#3561]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3561
[#3562]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3562
[#3564]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3564
[#3565]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3565
[#3566]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3566
[#3567]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3567
[#3568]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3568
[#3569]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3569
[#3570]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3570
[#3571]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3571
[#3572]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3572
[#3573]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3573
[#3575]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3575
[#3576]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3576
[#3577]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3577
[#3578]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3578
[#3579]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3579
[#3580]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3580
[#3581]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3581
[#3583]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3583
[#3584]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3584
[#3585]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3585
[#3586]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3586
[#3587]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3587
[#3588]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3588
[#3589]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3589
[#3590]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3590
[#3591]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3591
[#3592]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3592
[#3593]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3593
[#3594]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3594
[#3595]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3595
[#3596]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3596
[#3597]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3597
[#3598]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3598
[#3599]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3599
[#3600]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3600
[#3601]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3601
[#3602]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3602
[#3603]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3603
[#3604]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3604
[#3605]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3605
[#3606]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3606
[#3607]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3607
[#3608]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3608
[#3609]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3609
[#3610]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3610
[#3611]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3611
[#3612]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3612
[#3613]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3613
[#3614]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3614
[#3615]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3615
[#3616]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3616
[#3617]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3617
[#3618]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3618
[#3619]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3619
[#3620]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3620
[#3621]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3621
[#3622]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3622
[#3623]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3623
[#3624]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3624
[#3626]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3626
[#3627]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3627
[#3628]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3628
[#3629]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3629
[#3630]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3630
[#3631]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3631
[#3632]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3632
[#3633]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3633
[#3634]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3634
[#3635]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3635
[#3636]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3636
[#3637]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3637
[#3638]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3638
[#3639]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3639
[#3640]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3640
[#3641]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3641
[#3642]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3642
[#3644]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3644
[#3645]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3645
[#3646]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3646
[#3647]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3647
[#3648]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3648
[#3650]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3650
[#3651]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3651
[#3652]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3652
[#3653]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3653
[#3654]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3654
[#3656]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3656
[#3657]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3657
[#3658]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3658
[#3659]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3659
[#3660]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3660
[#3661]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3661
[#3664]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3664
[#3665]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3665
[#3666]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3666
[#3667]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3667
[#3669]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3669
[#3670]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3670
[#3671]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3671
[#3672]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3672
[#3678]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3678
[#3679]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3679
[#3680]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3680
[#3681]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3681
[#3682]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3682
[#3683]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3683
[#3684]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3684
[#3685]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3685
[#3690]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3690
[#3692]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3692
[#3693]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3693
[#3694]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3694
[#3695]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3695
[#3697]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3697
[#3698]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3698
[#3699]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3699
[#3700]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3700
[#3702]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3702
[#3704]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3704
[#3705]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3705
[#3708]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3708
[#3709]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3709
[#3710]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3710
[#3714]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3714
[#3715]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3715
[#3716]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3716
[#3719]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3719
[#3722]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3722
[#3723]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3723
[#3724]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3724
[#3725]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3725
[#3726]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3726
[#3728]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3728
[#3729]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3729
[#3731]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3731
[#3732]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3732
[#3735]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3735
[#3736]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3736
[#3739]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3739
[#3741]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3741
[#3743]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3743
[#3744]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3744
[#3745]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3745
[#3746]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3746
[#3747]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3747
[#3749]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3749
[#3750]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3750
[#3751]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3751
[#3762]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3762
[#3768]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3768
[#3770]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3770
[#3775]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3775
[#3777]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3777
[#3778]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3778
[#3779]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3779
[#3781]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3781
[#3783]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3783
[#3785]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3785
[#3790]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3790
[#3791]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3791
[#3792]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3792
[#3793]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3793
[#3794]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3794
[#3795]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3795
[#3796]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3796
[#3798]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3798
[#3799]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3799
[#3800]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3800
[#3801]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3801
[#3802]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3802
[#3804]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3804
[#3806]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3806
[#3807]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3807
[#3808]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3808
[#3809]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3809
[#3810]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3810
[#3811]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3811
[#3812]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3812
[#3815]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3815
[#3816]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3816
[#3817]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3817
[#3818]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3818
[#3819]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3819
[#3820]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3820
[#3821]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3821
[#3822]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3822
[#3823]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3823
[#3824]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3824
[#3825]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3825
[#3826]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3826
[#3827]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3827
[#3828]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3828
[#3830]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3830
[#3831]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3831
[#3832]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3832
[#3833]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3833
[#3834]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3834
[#3835]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3835
[#3836]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3836
[#3837]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3837
[#3841]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3841
[#3842]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3842
[#3843]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3843
[#3844]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3844
[#3845]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3845
[#3847]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3847
[#3848]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3848
[#3849]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3849
[#3851]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3851
[#3852]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3852
[#3853]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3853
[#3854]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3854
[#3855]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3855
[#3856]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3856
[#3860]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3860
[#3861]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3861
[#3863]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3863
[#3864]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3864
[#3866]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3866
[#3867]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3867
[#3868]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3868
[#3869]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3869
[#3874]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3874
[#3875]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3875
[#3876]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3876
[#3877]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3877
[#3878]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3878
[#3881]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3881
[#3882]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3882
[#3883]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3883
[#3884]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3884
[#3885]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3885
[#3886]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3886
[#3887]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3887
[#3888]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3888
[#3889]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3889
[#3890]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3890
[#3891]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3891
[#3892]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3892
[#3893]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3893
[#3894]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3894
[#3896]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3896
[#3898]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3898
[#3900]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3900
[#3901]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3901
[#3902]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3902
[#3904]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3904
[#3905]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3905
[#3906]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3906
[#3907]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3907
[#3908]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3908
[#3909]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3909
[#3912]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3912
[#3913]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3913
[#3914]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3914
[#3915]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3915
[#3916]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3916
[#3917]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3917
[#3919]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3919
[#3920]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3920
[#3921]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3921
[#3922]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3922
[#3923]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3923
[#3924]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3924
[#3925]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3925
[#3926]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3926
[#3928]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3928
[#3929]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3929
[#3930]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3930
[#3931]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3931
[#3932]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3932
[#3933]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3933
[#3934]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3934
[#3937]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3937
[#3938]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3938
[#3939]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3939
[#3942]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3942
[#3944]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3944
[#3945]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3945
[#3946]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3946
[#3954]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3954
[#3955]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3955
[#3957]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3957
[#3958]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3958

## [5.2.3]

### Fixed

- Fixed mobilecoind returning a gRPC invalid argument error instead of a not
  found error when ledger data is not found ([#3787])

### Changed

#### Deployments

- Add stack labels for service monitoring services ([#3782])

[#3787]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3787
[#3782]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3782

## [5.2.2]

### Changed

- Changed default for fog pubkey expiry from 100 to 10 ([#3773])

### Fixed

- Fog ledger shard last known block info ([#3771])

[#3771]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3771
[#3773]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3773

## [5.2.1]

### Changed

- Made polling interval of fog ledger block fetching configurable ([#3764])
- Improved performance of fog ledger shard block fetching ([#3765])

[#3764]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3764
[#3765]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3765

## [5.2.0]

### Added

- A `GetAllUnspentTxOuts` API call to mobilecoind ([#3752])
- Added the ability for Fog ledger and Fog ingest to get ledger data from a
  mobilecoind instance ([#3701], [#3748])

### Changed

- Improve parallel processing of monitor in mobilecoind ([#3673])
- Improve performance of SCP network tests ([#3713])
- Improve performance of fog test client ([#3737], [#3727])

#### Deployments

- Reduced fog ledger memory requests ([#3754])
- Fog ledger and ingest to use a network mobilecoind ([#3753])
- Refactored fog services chart  ([#3720], [#3707])

### Removed

- Removed use of OMAP in fog ledger router and fog veiw router ([#3718],
  [#3721])

### Fixed

#### Deployments

- Fixed alpha dev [(#3703)]

[#3673]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3673
[#3701]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3701
[#3703]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3703
[#3707]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3707
[#3713]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3713
[#3718]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3718
[#3720]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3720
[#3721]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3721
[#3727]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3727
[#3737]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3737
[#3748]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3748
[#3752]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3752
[#3753]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3753
[#3754]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3754

## [5.1.1]

### Fixed

#### Deployments

- fix port alignment for fog-ledger-router and grpc-gateway ([#3687])

[#3687]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3687

## [5.1.0]

### Changed

- Fog ledger will now update the prometheus metrics periodically ([#3649])

#### Deployments

- Reworked fog ledger and fog view deployments ([#3675], [#3668], [#3662])
- Add support for multiple fog report instances ([#3643])

#### Rust Dependencies

- Bump `grpcio` from 0.12.1 to 0.13.0 ([#3674])

[#3675]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3675
[#3674]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3674
[#3668]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3668
[#3662]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3662
[#3649]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3649
[#3643]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3643

## [5.0.8]

### Changed

- Previously the application running the ledger enclave would perform a periodic
  check to see if the ledger enclave was in a good state. Now all enclave
  runners will panic if an enclave call comes back with a fatal SGX error.
  ([#3526])

### Fixed

#### Deployments

- fix: shardOverlap ([#3545])

### Removed

#### Deployments

- removed backing up of ledger database ([#3558])

[#3545]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3545
[#3549]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3549
[#3558]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3558

## [5.0.7]

### Added

- Healthcheck to fog ledger enclave ([#3533])

### Fixed

#### Deployments

- fix: update shard values and defaults ([#3520])
- fix: lmdb bootstrap uses same volume for download and destination ([#3526])
- fix: startup probe uses 300 attempts to compensate for lmdb download times ([#3525])

[#3520]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3520
[#3525]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3525
[#3526]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3526
[#3533]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3530

## [5.0.6]

### Fixed

- fix: admin server for fog view & ledger routers should expose metrics ([#3486])

### Added

- feat: additional metrics for fog view & ledger routers and stores ([#3486])

## [5.0.5]

### Fixed

#### Deployments

- fix: remove client-auth-token from store configs ([#3387])
- feat: (helm) add ingress switch to fog-services for blue/green style deployments. ([#3389])

## [5.0.4]

### Fixed

#### CI/CD

- Helm: init containers, add startupprobes ([#3383])
- Removed block-v2 tests (commit [bb15dc](https://github.com/mobilecoinfoundation/mobilecoin/commit/bb15dc33a30b0931a892d6ff3f04c291dcd57d0e))
- Removed bv2 bootstrap (commit [1a9de0](https://github.com/mobilecoinfoundation/mobilecoin/commit/1a9de0c288b09c1a7ba731ebe40ad617b43dd8ff))

## [5.0.3]

### Fixed

#### CI/CD

- Ledger and watcher database restore in CD pipeline ([#3379])

[#3379]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3379

## [5.0.2]

### Added

- Add block signatures to mobilecoind-json block response ([#3366])

[#3366]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3366

## [5.0.1]

### Fixed

- GPG key used in CD pipeline ([#3361])

[#3361]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3361

## [5.0.0]

### Added

- The json slam report now contains the average slam rate ([#3080])
- Build time error messages will now be output for invalid `SGX_MODE` and `IAS_MODE` environment variables ([#3164])
- Added a new crate `mc-attest-verifier-config` crate which can be used to handle multiple enclave measurements and hardening advisories ([#3148])
- Add logic in consensus to drop clients that exceed a configurable number of failed tx proposals ([#3208], [#3155], [#3156])
- The `AdminServer` now allows passing of extra gRPC services ([#3242])
- [MCIP 61]: Add Defragmentation Memos ([#3170])
- The b58-decoder can now print public address hashes ([#3283])
- Fog view router supports sharding the fog storage. Provides a streaming and unary GRPC api. ([#3297])
- Fog ledger router supports sharding the key image storage. Provides a streaming and unary GRPC api. ([#3312], ([#3331])

### Fixed

- `mobilecoind` now produces SCIs with correct `tx_out_global_indices` values ([#3311])
- Enclave panic reporting to show the panic error ([#3274])
- `mc-crypto-keys` now includes `mc-util-serial` when `serde` feature is enabled ([#3303])

### Removed

- Removed the prometheus push setting in local network development/testing script ([#3124])
- Removed the `mc-crypto-dalek` crate ([#3282])

### Security

- Update Intel SGX SDK to 2.19.100.3 ([#3252])

### Changed

- `mobilecoind` now has its own version of the `LastBlockInfo` proto message. ([#3307])
- `mobilecoind` now exposes the chain-id of the chain it is connected to via rpc ([#3313])
- Metrics are now prefixed with the service names ([#2908], [#3322])
- Use "unknown" for `GIT_COMMIT` failures in logging output ([#3117])
- Update MSRV to 1.68.0 ([#3122])
- Unfork opentelmetry, use reqwest backend. Also removes use of openssl-sys ([#3154])
- Expose `SchnorrkelError` from `mc-crypto-keys` ([#3261])
- `mc-crypto-rand` has been renamed to `mc-rand` and published as a separate crate ([#3291])
- Reduce the number of info log messages from watcher DB ([#3301], [#3328])
- `mobilecoind` will now retry if a transaction fails ([#3308])

#### Github Actions

- Bump `actions/setup-go` from 3 to 4 ([#3251])
- Bump `docker/build-push-action` from 3 to 4 ([#3076])

#### Python Dependencies

- Bump `certifi` from 2021.10.8 to 2022.12.7 in /mobilecoind/strategies ([#2938])
- Bump `ipython` from 7.16.3 to 8.10.0 in /mobilecoind/strategies ([#3120])
- Bump `werkzeug` from 1.0.1 to 2.2.3 in /consensus/scp/viewer ([#3143])

#### Rust Dependencies

- Update `rust-toolchain` version to newer nightly "2023-01-22" ([#2999], [#3323])
- Bump `aes-gcm` from 0.9.4 to 0.10.1 ([#2806])
- Bump `anyhow` from 1.0.66 to 1.0.69 ([#3002], [#3108])
- Bump `assert_cmd` from 2.0.7 to 2.0.10 ([#3065], [#3277])
- Bump `backtrace` from 0.3.66 to 0.3.67 ([#3064])
- Bump `base64` from 0.13.1 to 0.21.0 ([#3003])
- Bump `bitflags` from 1.2.1 to 2.0.1 ([#3109], [#3250])
- Bump `blake2` from 0.10.4 to 0.10.6 ([#2859], [#2991])
- Bump `bumpalo` from 3.2.1 to 3.12.0 ([#3042], [#3039], [#3040], [#3041], [#3038])
- Bump `cargo_metadata` from 0.15.1 to 0.15.3 ([#3106])
- Bump `cc` from 1.0.74 to 1.0.79 ([#2957], [#2958], [#2959], [#2960], [#2961], [#3087], [#3090], [#3067], [#3068], [#3091])
- Bump `chrono` from 0.4.23 to 0.4.24 ([#3229])
- Bump `clap` from 4.0.29 to 4.1.11 ([#2980], [#3139], [#3187], [#3265])
- Bump `cookie` from 0.16.1 to 0.17.0 ([#3086])
- Bump `crc` from 3.0.0 to 3.0.1 in /fog/view/enclave/trusted ([#3069])
- Bump `crossbeam-channel` from 0.5.6 to 0.5.7 ([#3186])
- Bump `digest` from 0.10.5 to 0.10.6 ([#3006], [#3010], [#2937] , [#3052])
- Bump `fs_extra` from 1.2.0 to 1.3.0 ([#3104])
- Bump `futures` from 0.3.25 to 0.3.28 ([#3075], [#3300])
- Bump `grpcio` from 0.11.0 to 0.12.1 ([#2826], [#3134])
- Bump `hashbrown` from 0.13.1 to 0.13.2 in /consensus/enclave/trusted ([#3094])
- Bump `libc` from 0.2.137 to 0.2.140 ([#3014], [#3218])
- Bump `link-cplusplus` from 1.0.7 to 1.0.8 ([#3013])
- Bump `mc-oblivious-map` from 2.2 to 2.3 ([#3290])
- Bump `mc-oblivious-ram` from 2.2 to 2.3 ([#3290])
- Bump `mc-oblivious-traits` from 2.2 to 2.3 ([#3290])
- Bump `num_cpus` from 1.14.0 to 1.15.0 ([#3098])
- Bump `once_cell` from 1.16.0 to 1.17.1 ([#3057], [#3135], [#3137])
- Bump `pem` from 1.1.0 to 2.0.0 ([#3021], [#3045], [#3268])
- Bump `predicates` from 2.1.1 to 3.0.1 ([#2915], [#2996], [#3266])
- Bump `proc-macro2` from 1.0.47 to 1.0.51 ([#3015], [#3073], [#3103])
- Bump `proptest` from 1.0.0 to 1.1.0 ([#3113])
- Bump `prost` from 0.11.2 to 0.11.8 ([#3004], [#3012], [#3027], [#3099], [#3046], [#3165], [#3173])
- Bump `quote` from 1.0.21 to 1.0.26 ([#2982], [#3231])
- Bump `rayon` from 1.5.3 to 1.7.1 ([#3025], [#3196], [#3055])
- Bump `reqwest` from 0.11.12 to 0.11.14 ([#2990], [#3089])
- Bump `semver` from 1.0.14 to 1.0.17 ([#3026], [#3255])
- Bump `sentry` from 0.29.1 to 0.30.0 ([#3054], [#3116], [#3167])
- Bump `serde_json` from 1.0.87 to 1.0.94 ([#3023], [#3115], [#3199])
- Bump `serde_with` from 2.0.1 to 2.3.1 ([#3053], [#3222])
- Bump `serde` from 1.0.147 to 1.0.159 ([#3024], [#3011], [#3009], [#3028], [#3066], [#3213], [#3294])
- Bump `serial_test` from 0.9.0 to 1.0.0 ([#2989], [#3074])
- Bump `signal-hook` from 0.3.14 to 0.3.15 ([#3133])
- Bump `signature` from 1.6.4 to 2.0.0 ([#3299])
- Bump `syn` from 1.0.107 to 2.0.11 ([#3166], [#3295])
- Bump `tempfile` from 3.3.0 to 3.4.0 ([#3184])
- Bump `toml` from 0.5.9 to 0.7.3 ([#3093], [#3112], [#3249])
- Bump `tokio` from 1.16.1 to 1.25.0 ([#3278])
- Bump `walkdir` from 2.3.2 to 2.3.3 ([#3256])
- Bump `wasm-bindgen-test` from 0.3.33 to 0.3.34 ([#3105])
- Bump `wasm-bindgen` from 0.2.83 to 0.2.84 ([#3088])
- Remove `slog-gelf` ([#3278])
- Update `mbedtls`, `mbedtls-sys` forks to support newer rust nightlies, use newer `heapless` ([#2962], [#3206])
- Update to `curve25519-dalek-4.0.0-rc.1` ([#3193])
- Update from forked diesel to 2.0.3 ([#3304])

[MCIP 61]: https://github.com/mobilecoinfoundation/mcips/blob/main/text/0061-defrag-memos.md
[#2806]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2806
[#2826]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2826
[#2859]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2859
[#2908]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2908
[#2915]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2915
[#2937]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2937
[#2938]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2938
[#2957]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2957
[#2958]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2958
[#2959]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2959
[#2960]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2960
[#2961]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2961
[#2962]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2962
[#2980]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2980
[#2982]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2982
[#2989]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2989
[#2990]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2990
[#2991]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2991
[#2996]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2996
[#2999]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2999
[#3002]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3002
[#3003]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3003
[#3004]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3004
[#3006]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3006
[#3009]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3009
[#3010]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3010
[#3011]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3011
[#3012]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3012
[#3013]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3013
[#3014]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3014
[#3015]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3015
[#3021]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3021
[#3023]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3023
[#3024]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3024
[#3025]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3025
[#3026]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3026
[#3027]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3027
[#3028]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3028
[#3038]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3038
[#3039]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3039
[#3040]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3040
[#3041]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3041
[#3042]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3042
[#3045]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3045
[#3046]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3046
[#3052]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3052
[#3053]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3053
[#3054]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3054
[#3055]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3055
[#3057]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3057
[#3064]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3064
[#3065]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3065
[#3066]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3066
[#3067]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3067
[#3068]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3068
[#3069]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3069
[#3073]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3073
[#3074]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3074
[#3075]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3075
[#3076]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3076
[#3080]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3080
[#3086]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3086
[#3087]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3087
[#3088]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3088
[#3089]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3089
[#3090]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3090
[#3091]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3091
[#3093]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3093
[#3094]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3094
[#3098]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3098
[#3099]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3099
[#3103]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3103
[#3104]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3104
[#3105]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3105
[#3106]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3106
[#3108]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3108
[#3109]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3109
[#3112]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3112
[#3113]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3113
[#3115]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3115
[#3116]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3116
[#3117]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3117
[#3120]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3120
[#3122]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3122
[#3124]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3124
[#3133]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3133
[#3134]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3134
[#3135]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3135
[#3137]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3137
[#3139]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3139
[#3148]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3148
[#3154]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3154
[#3155]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3155
[#3156]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3156
[#3164]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3164
[#3165]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3165
[#3166]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3166
[#3167]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3167
[#3170]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3170
[#3173]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3173
[#3184]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3184
[#3186]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3186
[#3187]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3187
[#3193]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3193
[#3196]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3196
[#3199]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3199
[#3206]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3206
[#3208]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3208
[#3213]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3213
[#3218]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3218
[#3222]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3222
[#3229]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3229
[#3231]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3231
[#3242]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3242
[#3249]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3249
[#3250]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3250
[#3251]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3251
[#3252]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3252
[#3255]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3255
[#3256]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3256
[#3261]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3261
[#3265]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3265
[#3266]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3266
[#3268]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3268
[#3274]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3274
[#3277]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3277
[#3278]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3278
[#3282]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3282
[#3283]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3283
[#3290]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3290
[#3291]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3291
[#3294]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3294
[#3295]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3295
[#3297]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3297
[#3299]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3299
[#3300]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3300
[#3301]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3301
[#3303]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3303
[#3304]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3304
[#3307]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3307
[#3308]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3308
[#3311]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3311
[#3312]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3312
[#3313]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3313
[#3322]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3322
[#3323]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3323
[#3328]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3328
[#3331]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3331

## [4.1.0]

### Added

- `mobilecoind` now supports generating SCI transactions ([#3212], [#3214], [#3232])
- `mobilecoind-dev-faucet --activate` now auto-activates the faucet on startup ([#3062])
- `mc-transaction-signer` crate to define types for view-only accounts and offline signing ([#2926])

### Changed

- `mobilecoind-json` now always includes the `MaskedAmount` version in its responses ([#3036])
- Replace `tempdir` with `tempfile` ([#3211])
- Libraries used by client SDKs are now licensed under the Apache-2.0 license (servers remain GPLv3) ([#3092])
- Restore ability to read the port a gRPC server is listening on ([#3107])

### Fixed

- Fog view will no longer claim it's ready before ORAM is loaded ([#3149])

[#3212]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3212
[#3214]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3214
[#3232]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3232
[#3062]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3062
[#2926]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2926
[#3036]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3036
[#3211]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3211
[#3092]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3092
[#3107]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3107
[#3149]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3149

## [4.0.2]

### Fixed

- fix(charts): fix blocklist activation logic ([#3048])

[#3048]: https://github.com/mobilecoinfoundation/mobilecoin/pull/3048

## [4.0.1]

### Added

- Make the local network script support a dense3 network option ([#2988])
- HAProxy Ingress Blocklists ([#2952])

### Changed

- Improved performance of mobilecoind-dev-faucet for better load testing ([#2955])

[#2988]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2988
[#2952]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2952
[#2955]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2955

## [4.0.0]

### Added

- [MCIP 42]: Partial-fill rules for signed contingent input transactions
- [MCIP 43]: Consensus nodes will now sign and publish metadata about blocks
- [MCIP 54]: Transaction builder support for TxO memo fields for payment intent and request IDs
- [MCIP 55]: Nested multi-sig for minting transactions
- Services can now output JSON-formatted messages to stdout/stderr
- `mc-consensus-mint-client` now supports `--tombstone-from-node [mc://URI]` to set the tombstone block automatically
- `mc-consensus-mint-client` now supports `MintConfigTx` parameters from JSON files

### Changed

- [MCIP 52]: Transactions now sign a `TxSummary` instead of the previous `TxPrefix`, to aid with hardware wallet confirmations
- [MCIP 53]: Extend the `MintTx` to allow direct minting to fog-enabled addresses
- [MCIP 57]: Relax some constraints around ring signature contents in SCI transactions

#### Github Actions

- Bump `actions/checkout` from 2 to 3 ([#2113])
- Bump `actions/setup-python` from 3 to 4 ([#2114])
- Bump `docker/build-push-action` from 2 to 3 ([#2425])
- Bump `docker/login-action` from 1 to 2 ([#2428])
- Bump `docker/metadata-action` from 3 to 4 ([#2426])
- Bump `docker/setup-buildx-action` from 1 to 2 ([#2427])

#### Python Dependencies

- Bump `protobuf` from 3.19.4 to 3.19.5 in /mobilecoind/strategies ([#2602])

#### Rust Dependencies

- Bump `anyhow` from 1.0.57 to 1.0.61 ([#2177], [#2365], [#2389])
- Bump `assert_cmd` from 2.0.4 to 2.0.5 ([#2742])
- Bump `async-channel` from 1.6.1 to 1.7.1 ([#2364], [#2386])
- Bump `backtrace` from 0.3.65 to 0.3.66 ([#2237])
- Bump `base64` from 0.13.0 to 0.13.1 ([#2755], [#2752], [#2754], [#2751], [#2753])
- Bump `cargo_metadata` from 0.14.2 to 0.15.1 ([#2186], [#2768])
- Bump `cbindgen` from 0.23.0 to 0.24.3 ([#2103], [#2117])
- Bump `cc` from 1.0.73 to 1.0.74 ([#2795], [#2797], [#2798], [#2799], [#2800])
- Bump `chrono` from 0.4.19 to 0.4.22 ([#2349], [#2381], [#2404])
- Bump `clap` from 3.1.18 to 4.0.18 ([#2135], [#2152], [#2182], [#2217], [#2263], [#2264], [#2327], [#2470], [#2561], [#2665], [#2715], [#2756])
- Bump `cookie` from 0.16.0 to 0.16.1 ([#2610])
- Bump `criterion` from 0.3.5 to 0.4.0 ([#2238], [#2510])
- Bump `crossbeam-channel` from 0.5.4 to 0.5.6 ([#2154], [#2301])
- Bump `digest` from 0.10.3 to 0.10.5 ([#2560], [#2596], [#2556], [#2553])
- Bump `futures` from 0.3.21 to 0.3.25 ([#2403], [#2451], [#2743])
- Bump `generic-array` from 0.14.5 to 0.14.6 ([#2336])
- Bump `getrandom` from 0.2.6 to 0.2.8 ([#2138], [#2137], [#2744])
- Bump `grpcio` from 0.10.2 to 0.11.0 ([#2207], [#2529])
- Bump `hashbrown` from 0.12.1 to 0.12.3 ([#2247])
- Bump `iana-time-zone` from 0.1.44 to 0.1.47 ([#2453])
- Bump `itertools` from 0.10.3 to 0.10.5 ([#2574])
- Bump `libc` from 0.2.126 to 0.2.137 ([#2384], [#2409], [#2569], [#2631], [#2702], [#2769], [#2775])
- Bump `libz-sys` from 1.1.6 to 1.1.8 ([#2069])
- Bump `link-cplusplus` from 1.0.6 to 1.0.7 ([#2423])
- Bump `mockall` from 0.11.1 to 0.11.3 ([#2300], [#2727])
- Bump `more-asserts` from 0.2.2 to 0.3.1 ([#2087], [#2645])
- Bump `num_cpus` from 1.13.1 to 1.14.0 ([#2825])
- Bump `once_cell` from 1.10.0 to 1.16.0 ([#2016], [#2229], [#2410], [#2408], [#2480], [#2579], [#2796])
- Bump `pem` from 1.0.2 to 1.1.0 ([#2262])
- Bump `percent-encoding` from 2.1.0 to 2.2.0 ([#2499])
- Bump `pkg-config` from 0.3.25 to 0.3.26 ([#2774], [#2778], [#2779], [#2776], [#2777])
- Bump `primitive-types` from 0.11.1 to 0.12.1 ([#2575], [#2787])
- Bump `proc-macro2` from 1.0.39 to 1.0.47 ([#2173], [#2346], [#2633], [#2723])
- Bump `prometheus` from 0.13.1 to 0.13.3 ([#2498], [#2758])
- Bump `prost` from 0.11.0 to 0.11.2 ([#2051], [#2048], [#2049], [#2047], [#2050], [#2320], [#2824], [#2818], [#2819], [#2820])
- Bump `quote` from 1.0.18 to 1.0.21 ([#2175], [#2190], [#2343])
- Bump `r2d2` from 0.8.9 to 0.8.10 ([#2187])
- Bump `rand_core` from 0.6.3 to 0.6.4 ([#2541], [#2538], [#2534], [#2539], [#2537])
- Bump `regex` from 1.5.4 to 1.7.0 ([#2091], [#2230], [#2841])
- Bump `reqwest` from 0.11.10 to 0.11.12 ([#2128], [#2578])
- Bump `retry` from 1.3.1 to 2.0.0 ([#2570])
- Bump `semver` from 1.0.9 to 1.0.14 ([#2124], [#2219], [#2344], [#2540])
- Bump `sentry` from 0.26.0 to 0.27.0 ([#2176])
- Bump `serde` from 1.0.137 to 1.0.147 ([#2248], [#2244], [#2246], [#2242], [#2245], [#2372], [#2368], [#2370], [#2369], [#2371], [#2424], [#2420], [#2418], [#2422], [#2594], [#2592], [#2598], [#2599], [#2597], [#2757], [#2748], [#2749], [#2747], [#2750])
- Bump `serde_json` from 1.0.81 to 1.0.87 ([#2213], [#2345], [#2421], [#2701], [#2740])
- Bump `serial_test` from 0.6.0 to 0.9.0 ([#2090], [#2201], [#2385])
- Bump `sha2` from 0.10.2 to 0.10.6 ([#2482], [#2475], [#2476], [#2477], [#2479], [#2559], [#2551], [#2554], [#2557], [#2558])
- Bump `sha3` from 0.10.1 to 0.10.6 ([#2330], [#2358], [#2481], [#2478], [#2562], [#2603], [#2741], [#2738])
- Bump `signature` from 1.5.0 to 1.6.4 ([#2402], [#2511], [#2669])
- Bump `smallvec` from 1.2.0 to 1.8.0 ([#2161], [#2160], [#2158], [#2159])
- Bump `syn` from 1.0.95 to 1.0.103 ([#2082], [#2174], [#2347], [#2568], [#2608], [#2677], [#2739])
- Bump `thread_local` from 1.0.1 to 1.1.4 ([#2162])
- Bump `tiny-bip39` from 0.8.2 to 1.0.0 ([#2146])
- Bump `url` from 2.2.2 to 2.3.1 ([#2490], [#2496], [#2495], [#2494], [#2497], [#2523])
- Bump `wasm-bindgen` from 0.2.82 to 0.2.83 ([#2509])
- Bump `wasm-bindgen-test` from 0.3.28 to 0.3.33 ([#2508], [#2646])
- Bump `zeroize` from 1.5.5 to 1.5.7 ([#2212], [#2210], [#2211], [#2209], [#2294], [#2292], [#2291], [#2293])

### Removed

- [`libmobilecoin`](https://github.com/mobilecoinofficial/libmobilecoin) and [`android-bindings`](https://github.com/mobilecoinofficial/android-bindings) have been moved to external repositories

### Security

- [MCIP 56]: Make the enclave enforce unique nonces per-token (improved fix for TOB-MCCT-4).
- TOB-MCCT-5: Reject transactions where the client's fee map differs from the consensus enclave's.
- Update SGX SDK to 2.18.

[MCIP 42]: https://github.com/mobilecoinfoundation/mcips/blob/main/text/0042-partial-fill-rules.md
[MCIP 43]: https://github.com/mobilecoinfoundation/mcips/blob/main/text/0043-block-metadata.md
[MCIP 52]: https://github.com/mobilecoinfoundation/mcips/blob/main/text/0052-tx-summary-digest.md
[MCIP 53]: https://github.com/mobilecoinfoundation/mcips/blob/main/text/0053-minting-to-fog-addresses.md
[MCIP 54]: https://github.com/mobilecoinfoundation/mcips/blob/main/text/0054-rth-payment-id-memos.md
[MCIP 55]: https://github.com/mobilecoinfoundation/mcips/blob/main/text/0055-nested-multi-sigs.md
[MCIP 56]: https://github.com/mobilecoinfoundation/mcips/blob/main/text/0056-tx-fee-map-digest.md
[MCIP 57]: https://github.com/mobilecoinfoundation/mcips/blob/main/text/0057-update-mixin-uniqueness-rules-for-scis.md
[#2113]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2113
[#2114]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2114
[#2425]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2425
[#2428]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2428
[#2426]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2426
[#2427]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2427
[#2602]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2602
[#2177]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2177
[#2365]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2365
[#2389]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2389
[#2742]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2742
[#2364]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2364
[#2386]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2386
[#2237]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2237
[#2755]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2755
[#2752]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2752
[#2754]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2754
[#2751]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2751
[#2753]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2753
[#2186]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2186
[#2768]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2768
[#2103]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2103
[#2117]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2117
[#2795]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2795
[#2797]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2797
[#2798]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2798
[#2799]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2799
[#2800]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2800
[#2349]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2349
[#2381]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2381
[#2404]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2404
[#2135]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2135
[#2152]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2152
[#2182]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2182
[#2217]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2217
[#2263]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2263
[#2264]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2264
[#2327]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2327
[#2470]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2470
[#2561]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2561
[#2665]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2665
[#2715]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2715
[#2756]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2756
[#2610]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2610
[#2238]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2238
[#2510]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2510
[#2154]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2154
[#2301]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2301
[#2560]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2560
[#2596]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2596
[#2556]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2556
[#2553]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2553
[#2403]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2403
[#2451]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2451
[#2743]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2743
[#2336]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2336
[#2138]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2138
[#2137]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2137
[#2744]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2744
[#2207]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2207
[#2529]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2529
[#2247]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2247
[#2453]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2453
[#2574]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2574
[#2384]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2384
[#2409]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2409
[#2569]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2569
[#2631]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2631
[#2702]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2702
[#2769]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2769
[#2775]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2775
[#2069]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2069
[#2423]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2423
[#2300]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2300
[#2727]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2727
[#2087]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2087
[#2645]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2645
[#2825]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2825
[#2016]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2016
[#2229]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2229
[#2410]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2410
[#2408]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2408
[#2480]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2480
[#2579]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2579
[#2796]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2796
[#2262]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2262
[#2499]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2499
[#2774]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2774
[#2778]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2778
[#2779]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2779
[#2776]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2776
[#2777]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2777
[#2575]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2575
[#2787]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2787
[#2173]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2173
[#2346]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2346
[#2633]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2633
[#2723]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2723
[#2498]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2498
[#2758]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2758
[#2051]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2051
[#2048]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2048
[#2049]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2049
[#2047]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2047
[#2050]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2050
[#2320]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2320
[#2824]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2824
[#2818]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2818
[#2819]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2819
[#2820]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2820
[#2175]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2175
[#2190]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2190
[#2343]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2343
[#2187]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2187
[#2541]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2541
[#2538]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2538
[#2534]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2534
[#2539]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2539
[#2537]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2537
[#2091]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2091
[#2230]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2230
[#2841]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2841
[#2128]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2128
[#2578]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2578
[#2570]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2570
[#2124]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2124
[#2219]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2219
[#2344]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2344
[#2540]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2540
[#2176]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2176
[#2248]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2248
[#2244]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2244
[#2246]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2246
[#2242]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2242
[#2245]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2245
[#2372]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2372
[#2368]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2368
[#2370]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2370
[#2369]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2369
[#2371]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2371
[#2424]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2424
[#2420]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2420
[#2418]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2418
[#2422]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2422
[#2594]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2594
[#2592]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2592
[#2598]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2598
[#2599]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2599
[#2597]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2597
[#2757]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2757
[#2748]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2748
[#2749]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2749
[#2747]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2747
[#2750]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2750
[#2213]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2213
[#2345]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2345
[#2421]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2421
[#2701]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2701
[#2740]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2740
[#2090]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2090
[#2201]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2201
[#2385]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2385
[#2482]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2482
[#2475]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2475
[#2476]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2476
[#2477]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2477
[#2479]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2479
[#2559]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2559
[#2551]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2551
[#2554]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2554
[#2557]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2557
[#2558]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2558
[#2330]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2330
[#2358]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2358
[#2481]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2481
[#2478]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2478
[#2562]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2562
[#2603]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2603
[#2741]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2741
[#2738]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2738
[#2402]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2402
[#2511]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2511
[#2669]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2669
[#2161]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2161
[#2160]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2160
[#2158]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2158
[#2159]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2159
[#2082]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2082
[#2174]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2174
[#2347]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2347
[#2568]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2568
[#2608]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2608
[#2677]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2677
[#2739]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2739
[#2162]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2162
[#2146]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2146
[#2490]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2490
[#2496]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2496
[#2495]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2495
[#2494]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2494
[#2497]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2497
[#2523]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2523
[#2509]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2509
[#2508]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2508
[#2646]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2646
[#2212]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2212
[#2210]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2210
[#2211]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2211
[#2209]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2209
[#2294]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2294
[#2292]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2292
[#2291]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2291
[#2293]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2293

## [3.0.0]

### Added

- Add `Chain-ID` gRPC metadata ([MCIP #49](https://github.com/mobilecoinfoundation/mcips/pull/49)) to provide additional runtime disambiguation between clients and servers.
- Add a required `--chain-id` command-line arguments to consensus and fog servers.
- Add an optional `--chain-id` command-line argument to `mobilecoind`.
- Support using environment variables to set values for nearly all command-line arguments.
- Update CI deployments to use zerossl instead of letsencrypt.
- Add a `--hash-tx-file` subcommand to print the hash of a `mint-tx` or `mint-config-tx` file.
- Add the current block info (fee map, block version, etc.) to the response message for `mobilecoind_api.GetNetworkStatus`.
- Make Jaeger telemetry opt-in using `MC_TELEMETRY=1`.
- Add a `--block-query-batch-size` parameter to fog-view. This makes fog-view load more data at once from postgres, and helps it to start up faster even if there is high
  network latency in the connection to postgres. This defaults to 1000 now, where previous behavior corresponds to a value of 1.

### Fixes

- Update `mc-consensus-mint-client` to check that public addresses for minting targets do not have a configured fog server.
- Update to `android-bindings` and `libmobilecoin` RNG APIs to assist in idempotent transactions.

### Security

- TOB-MCCT-4: Make minting nonces unique per-token.
- Build with SGX SDK 2.17.1 to mitigate and account for INTEL-SA-00657.

## [2.0.0] - 2022-07-25

### Fixed

#### CI/CD

- Fix metadata script for new release branch patterns. ([#2298])

### Security

- Bump SGX to 2.17, mitigate INTEL-SA-00615

## [1.2.2] - 2022-06-17

### Changed

- Updated SGX to 2.16

### Rust Dependencies

- Updated `rust-toolchain` version to newer nightly
  - enables use of [Generic Associated Types](https://github.com/rust-lang/rust/issues/44265) and [static async fn in traits](https://github.com/rust-lang/rust/issues/91611)
- Replaced `datatest` with a custom `test_with_data` macro.
- Replace `structopt` with `clap`.
- Updated `grpcio` from 0.9 to 0.10.

## [1.2.1] - UNRELEASED

### Changed

- Expose the ability to get a TX shared secret to iOS SDK
- Restore the ability to derive an account from legacy root entropy to iOS SDK
- Improve the construction of `Amount` objects from Android SDK

### Fixed

- Fix panic when consensus service is configured for multiple tokens but still running in MOB-only block-version 0 mode.

## [1.2.0] - UNRELEASED

### Added

- Fog is now part of this repository
- Fog Ledger key image checks are now oblivious ([fog #101](https://github.com/mobilecoinfoundation/fog/pull/101))
- Fog View OMAP size configurable via environment
- Fog Overseer utility for monitoring Fog Ingest instances
- Fog Ingest Client CLI now allows queries to the `get_ingress_key_record` API
- Block versioning / protocol evolution ([MCIP #26])
- In Block Version 1 (to be enabled along with block version 2):
  - Required Transaction Memos ([MCIP #3])
  - Recoverable Transaction History ([MCIP #4])
- In Block Version 2 (to be enabled after network has been upgraded):
  - Confidential Multi-Token Support ([MCIP #25])
  - Minting support for non-MOB tokens ([MCIP #37])
  - Verifiable burning for any token ([MCIP #35])
  - Standardized Addresses for common purposes ([MCIP #36])
- In Block Version 3 (will be enabled in a future release):
  - Require TxOuts to be sorted in TxProposal ([MCIP #34]).

### Changed

- Enable `Bitcode` for `libmobilecoin`, reduce mobile artifact size by ~25% ([#1124])
- mobilecoind will now exit on startup when a ledger migration is necessary, unless the new `--ledger-db-migrate` command line argument is used, in which case it will migrate automatically. This flag does not do anything if the Ledger DB does not exist.
- Bump SGX versions to 2.16. ([#1101], [#2018])
- Increase the maximum tombstone block for transactions to `20,160` from `100`.
- Lock enclave no-debug mode when building for IAS production.
- Update Rust toolchain to `nightly-2021-07-21`.

#### Python

- Bump `ipython` from 7.8.0 to 7.16.3 ([#1333])
- Bump `protobuf` from 3.10.0 to 3.15.0 ([#1477])

#### Rust Dependencies

- Upgrade rust toolchain to `nightly-2022-04-29` ([#1613], [#1888])
- Replace `datatest` with a custom `test_with_data` attribute macro ([#1556])
- Replace `structopt` with `clap`, and add support for env overrides for all flags ([#1541])

- Fork `bulletproofs` to `bulletproofs-og` to use dalek upstream, fix clippy issues from upstream.
- Fork `cpufeatures` to disable `CPUID` usage, use fork in enclaves (cargo bug prevents upstreaming)
- Fork `opentelemetry` to update some of its dependencies. ([#1918])
- Fork `schnorrkel` to `schnorrkel-og`, to use dalek upstream
- Unfork `aes-gcm` and update to 0.9.2, use forked `mc-oblivious-aes-gcm` crate in the Fog hint decryption routines
- Unfork `cpuid-bool`, not used anymore
- Unfork `grpcio` and bump from 0.6 to 0.10.3. ([#1592], [#1717], [#1814])
- Unfork `prost` from bump from 0.8.0 to 0.10.3 ([#898], [#1109], [#1728], [#1805], [#1806], [#1807], [#1808], [#1809], [#1926], [#1927], [#1929], [#1930])
- Update `cmake` fork to git-5f89f90ee5d7789832963bffdb2dcb5939e6199c
- Update `curve25519-dalek` fork from 4.0.0-pre.0 to 4.0.0-pre.2
- Update `ed25519-dalek` fork to support new rust nightlies
- Update `mbedtls`, `mbedtls-sys` forks to support newer rust nightlies, use newer `spin`
- Update `x25519-dalek` fork to support newer rust nightlies

- Bump `aead` from 0.3.2 to 0.4.3 ([#1389])
- Bump `aes-gcm` from 0.9.2 to 0.9.4
- Bump `aes` from 0.7.4 to 0.7.5
- Bump `anyhow` from 1.0.39 to 1.0.57 ([#1013], [#1146], [#1265], [#1341], [#1529], [#1578], [#1837])
- Bump `arrayvec` from 0.5.2 to 0.7.1 ([#980])
- Bump `assert_cmd` from 2.0.2 to 2.0.4 ([#1314])
- Bump `backtrace` from 0.3.55 to 0.3.65 ([#982], [#1143], [#1392], [#1817])
- Bump `base64` from 0.12.3 to 0.13.0
- Bump `bincode` from 1.3.1 to 1.3.3 ([#1056])
- Bump `bindgen` from 0.51.1 to 0.59.2
- Bump `bitflags` from 1.2.1 to 1.3.2 ([#1016])
- Bump `blake2` from 0.9.1 to 0.10.4 ([#1520])
- Bump `bs58` from 0.3.1 to 0.4.0 ([#948])
- Bump `cargo-emit` from 0.1.1 to 0.2.1 ([#1045], [#990], [#1000], [#937], [#968])
- Bump `cargo_metadata` from 0.9.1 to 0.14.2 ([#949], [#1135], [#1502])
- Bump `cbindgen` from 0.14.3 to 0.23.0 ([#1020], [#1702], [#1824], [#1836])
- Bump `cc` from 1.0.66 to 1.0.73 ([#919], [#920], [#983], [#985], [#1094], [#1095], [#1096], [#1097], [#1099], [#1164], [#1165], [#1166], [#1167], [#1168], [#1497], [#1498], [#1499], [#1500], [#1501])
- Bump `cfg-if` from 0.1.10 to 1.0.0
- Bump `chrono` from 0.4.11 to 0.4.19 ([#959])
- Bump `clap` from 3.1.6 to 3.1.18 ([#1762], [#1825], [#1847], [#1904], [#1957])
- Bump `cookie` from 0.14.3 to 0.16.0 ([#1034], [#1271])
- Bump `crc` from 1.8.1 to 2.0.0 ([#1018], [#1138], [#1857])
- Bump `criterion` from 0.3.2 to 0.3.5 ([#1059])
- Bump `crossbeam-channel` from 0.5.0 to 0.5.4 ([#1039], [#1313], [#1678])
- Bump `diesel-derive-enum` from 1.1.1 to 1.1.2 ([#1311])
- Bump `diesel` from 1.4.7 to 1.4.8 ([#1061])
- Bump `digest` from 0.9.0 to 0.10.1
- Bump `dirs` from 2.0.2 to 4.0.0 ([#1071])
- Bump `displaydoc` from 0.2.0 to 0.2.3 ([#936], [#933], [#995])
- Bump `ed25519` from 1.0.1 to 1.5.0 ([#1179], [#1679], [#1950])
- Bump `futures` from 0.3.8 to 0.3.21 ([#1017], [#1262], [#1458])
- Bump `generic-array` from 0.14.4 to 0.14.5 ([#1315])
- Bump `getrandom` from 0.1.13, 0.2.2 to 0.2.6 ([#986], [#1052], [#1031], [#1310], [#1387], [#1532], [#1531], [#1714], [#1712])
- Bump `ghash` from 0.4.2 to 0.4.4
- Bump `hashbrown` from 0.6.3 to 0.12.1 ([#899], [#1915])
- Bump `hex` from 0.4.2 to 0.4.3 ([#1006], [#923], [#909], [#975], [#913])
- Bump `hkdf` from 0.9.0 to 0.12.3 ([#1345])
- Bump `hmac` from 0.7.1 to 0.12.1 ([#660], [#1345])
- Bump `hostname` from 0.1.5 to 0.3.1 ([#902])
- Bump `itertools` from 0.10.1 to 0.10.3 ([#1200])
- Bump `jni` from 0.16.0 to 0.19.0 ([#1012])
- Bump `libc` from 0.2.97 to 0.2.125 ([#1007], [#1070], [#1112], [#1134], [#1141], [#1159], [#1239], [#1348], [#1365], [#1391], [#1492], [#1525], [#1676], [#1782], [#1826], [#1887])
- Bump `libz-sys` from 1.1.4 to 1.1.6 ([#1591], [#1873])
- Bump `link-cplusplus` from 1.0.5 to 1.0.6 ([#1171])
- Bump `mockall` from 0.8.3 to 0.11.0 ([#956], [#1240])
- Bump `more-asserts` from 0.2.1 to 0.2.2 ([#1174])
- Bump `nix` from 0.18.0 to 0.22.1 ([#1022])
- Bump `num_cpus` from 1.13.0 to 1.13.1 ([#1261])
- Bump `once_cell` from 1.5.2 to 1.9.0 ([#998], [#1249])
- Bump `packed_simd_2` from 0.3.4 to 0.3.7
- Bump `pem` from 0.8.2 to 0.8.3 ([#957], [#1087], [#1131], [#1279])
- Bump `pkg-config` from 0.3.17 to 0.3.25 ([#915], [#925], [#965], [#967], [#1033], [#1072], [#1066], [#1067], [#1068], [#1069], [#1125], [#1126], [#1127], [#1128], [#1133], [#1235], [#1236], [#1237], [#1238], [#1241], [#1750], [#1751], [#1752], [#1753], [#1755])
- Bump `polyval` from 0.5.1 to 0.5.3
- Bump `predicates` from 1.0.5 to 2.1.1 ([#1142], [#1306])
- Bump `proc-macro2` from 1.0.24 to 1.0.38 ([#1104], [#1130], [#1268], [#1777], [#1938])
- Bump `prometheus` from 0.9.0 to 0.13.0 ([#1002], [#1079])
- Bump `proptest` from 0.10.1 to 1.0.0 ([#952])
- Bump `protobuf` from 2.22.1 to 2.27.1 ([#1754])
- Bump `quote` from 0.6.13 to 1.0.18 ([#1092], [#1355], [#1677], [#1716], [#1795])
- Bump `rand_chacha` from 0.3.0 to 0.3.1 ([#1057])
- Bump `rand_core` from 0.6.2 to 0.6.3 ([#921], [#930], [#947], [#977], [#1046])
- Bump `rand_hc` from 0.3.0 to 0.3.1 ([#916], [#972], [#976], [#988], [#1019])
- Bump `rand` from 0.8.3 to 0.8.5 ([#911], [#914], [#928], [#999], [#1041], [#1484], [#1485], [#1486], [#1487], [#1489])
- Bump `rayon` from 1.3.0 to 1.5.2 ([#992], [#1050], [#1812], [#1812])
- Bump `regex` from 1.3.7 to 1.5.5 ([#1432], [#1590])
- Bump `reqwest` from 0.10.6 to 0.10.10 ([#1054], [#1622])
- Bump `retry` from 1.2.0 to 1.3.0 ([#1036])
- Bump `rocket` from 0.4.6 to 0.5.0-rc2
- Bump `rusoto_s3` from 0.42 to 0.48. ([#1912])
- Bump `secrecy` from 0.4.1 to 0.8.0 ([#950], [#1043])
- Bump `semver` from 0.11.0 to 1.0.9 ([#1459], [#1528], [#1715], [#1900])
- Bump `sentry` from 0.24.3 to 0.25.0 ([#1563])
- Bump `serde_json` from 1.0.60 to 1.0.81 ([#1023], [#1155], [#1170], [#1278], [#1322], [#1344], [#1488], [#1916])
- Bump `serde` from 1.0.118 to 1.0.137 ([#939], [#940], [#941], [#991], [#996], [#1273], [#1274], [#1275], [#1276], [#1277], [#1350], [#1351], [#1363], [#1383], [#1386], [#1894], [#1895], [#1897], [#1901], [#1903])
- Bump `serial_test_derive` from 0.5.0 to 0.5.1 ([#1001])
- Bump `serial_test` from 0.5.0 to 0.5.1 ([#1044])
- Bump `sha2` from 0.8.1 to 0.10.2 ([#1512], [#1509])
- Bump `sha3` from 0.9.1 to 0.10.0
- Bump `signal-hook` from 0.3.4 to 0.3.13 ([#1008], [#1263])
- Bump `signature` from 0.2.2 to 1.4.0 ([#1115])
- Bump `siphasher` from 0.3.1 to 0.3.10 ([#942], [#1003], [#1321], [#1579])
- Bump `slog-async` from 2.5.0 to 2.7.0 ([#1060])
- Bump `slog-atomic` from 3.0.0 to 3.1.0 ([#1010])
- Bump `slog-json` from 2.3.0 to 2.6.1 ([#978], [#1343], [#1757])
- Bump `slog-json` from 2.3.0 to 2.4.0
- Bump `slog-scope` from 4.3.0 to 4.4.0 ([#1049])
- Bump `slog-stdlog` from 4.1.0 to 4.1.1 ([#1692])
- Bump `slog-term` from 2.6.0 to 2.8.0 ([#1042], [#1524])
- Bump `subtle` from 1.0.0 to 2.4.1
- Bump `syn` from 0.15.44 to 1.0.94 ([#979], [#1064], [#1090], [#1098], [#1132], [#1291], [#1332], [#1642], [#1713], [#1776], [#1886], [#1956], [#1976])
- Bump `tempfile` from 3.2.0 to 3.3.0 ([#1758])
- Bump `tiny-bip39` from 0.8.0 to 0.8.2 ([#1053], [#1080])
- Bump `toml` from 0.5.7 to 0.5.9 ([#1011], [#1815])
- Bump `url` from 2.1.1 to 2.2.2 ([#951])
- Bump `walkdir` from 2.3.1 to 2.3.2 ([#997], [#962], [#931], [#974], [#922])
- Bump `yaml-rust` from 0.4.4 to 0.4.5 ([#993])
- Bump `zeroize` from 1.2.0 to 1.5.5 ([#908], [#1027], [#1028], [#1029], [#1156], [#1360], [#1366], [#1656], [#1896], [#1898], [#1899], [#1902])

### Removed

- The `slam` test utility, in favor of `fog-distribution` ([#1611])
- Support for root entropy-based key derivation in test keys/ledgers ([#1893])
- The `pretty_assertions` dependency ([#1055], [#1078], [#1431], [#1610], [#1657])

### Fixed

- Fog ingest state file handling is more resilient ([#1358])
- Fog services sometimes returned the wrong grpc error code for attestation failures
- Added retries for connectivity issues with Postgres database in Fog services

### Security

- Fixed a problem with data authentication in the Fog OCALL Oram Storage interface (Thanks to [@AmbitionXiang] for reporting!, [#1576])

[MCIP #3]: https://github.com/mobilecoinfoundation/mcips/blob/main/text/0003-encrypted-memos.md
[MCIP #4]: https://github.com/mobilecoinfoundation/mcips/blob/main/text/0004-recoverable-transaction-history.md
[MCIP #25]: https://github.com/mobilecoinfoundation/mcips/blob/main/text/0025-confidential-token-ids.md
[MCIP #26]: https://github.com/mobilecoinfoundation/mcips/blob/main/text/0026-block-version-based-protocol-evolution.md
[MCIP #34]: https://github.com/mobilecoinfoundation/mcips/blob/main/text/0034-sorted-transaction-outputs.md
[MCIP #35]: https://github.com/mobilecoinfoundation/mcips/blob/main/text/0035-verifiable-burning.md
[MCIP #36]: https://github.com/mobilecoinfoundation/mcips/blob/main/text/0036-reserved-subaddresses.md
[MCIP #37]: https://github.com/mobilecoinfoundation/mcips/blob/main/text/0036-reserved-subaddresses.md
[#660]: https://github.com/mobilecoinfoundation/mobilecoin/pull/660
[#898]: https://github.com/mobilecoinfoundation/mobilecoin/pull/898
[#899]: https://github.com/mobilecoinfoundation/mobilecoin/pull/899
[#902]: https://github.com/mobilecoinfoundation/mobilecoin/pull/902
[#908]: https://github.com/mobilecoinfoundation/mobilecoin/pull/908
[#909]: https://github.com/mobilecoinfoundation/mobilecoin/pull/909
[#911]: https://github.com/mobilecoinfoundation/mobilecoin/pull/911
[#913]: https://github.com/mobilecoinfoundation/mobilecoin/pull/913
[#914]: https://github.com/mobilecoinfoundation/mobilecoin/pull/914
[#915]: https://github.com/mobilecoinfoundation/mobilecoin/pull/915
[#916]: https://github.com/mobilecoinfoundation/mobilecoin/pull/916
[#919]: https://github.com/mobilecoinfoundation/mobilecoin/pull/919
[#920]: https://github.com/mobilecoinfoundation/mobilecoin/pull/920
[#921]: https://github.com/mobilecoinfoundation/mobilecoin/pull/921
[#922]: https://github.com/mobilecoinfoundation/mobilecoin/pull/922
[#923]: https://github.com/mobilecoinfoundation/mobilecoin/pull/923
[#925]: https://github.com/mobilecoinfoundation/mobilecoin/pull/925
[#928]: https://github.com/mobilecoinfoundation/mobilecoin/pull/928
[#930]: https://github.com/mobilecoinfoundation/mobilecoin/pull/930
[#931]: https://github.com/mobilecoinfoundation/mobilecoin/pull/931
[#933]: https://github.com/mobilecoinfoundation/mobilecoin/pull/933
[#936]: https://github.com/mobilecoinfoundation/mobilecoin/pull/936
[#937]: https://github.com/mobilecoinfoundation/mobilecoin/pull/937
[#939]: https://github.com/mobilecoinfoundation/mobilecoin/pull/939
[#940]: https://github.com/mobilecoinfoundation/mobilecoin/pull/940
[#941]: https://github.com/mobilecoinfoundation/mobilecoin/pull/941
[#942]: https://github.com/mobilecoinfoundation/mobilecoin/pull/942
[#947]: https://github.com/mobilecoinfoundation/mobilecoin/pull/947
[#948]: https://github.com/mobilecoinfoundation/mobilecoin/pull/948
[#949]: https://github.com/mobilecoinfoundation/mobilecoin/pull/949
[#950]: https://github.com/mobilecoinfoundation/mobilecoin/pull/950
[#951]: https://github.com/mobilecoinfoundation/mobilecoin/pull/951
[#952]: https://github.com/mobilecoinfoundation/mobilecoin/pull/952
[#956]: https://github.com/mobilecoinfoundation/mobilecoin/pull/956
[#957]: https://github.com/mobilecoinfoundation/mobilecoin/pull/957
[#959]: https://github.com/mobilecoinfoundation/mobilecoin/pull/959
[#962]: https://github.com/mobilecoinfoundation/mobilecoin/pull/962
[#965]: https://github.com/mobilecoinfoundation/mobilecoin/pull/965
[#967]: https://github.com/mobilecoinfoundation/mobilecoin/pull/967
[#968]: https://github.com/mobilecoinfoundation/mobilecoin/pull/968
[#972]: https://github.com/mobilecoinfoundation/mobilecoin/pull/972
[#974]: https://github.com/mobilecoinfoundation/mobilecoin/pull/974
[#975]: https://github.com/mobilecoinfoundation/mobilecoin/pull/975
[#976]: https://github.com/mobilecoinfoundation/mobilecoin/pull/976
[#977]: https://github.com/mobilecoinfoundation/mobilecoin/pull/977
[#978]: https://github.com/mobilecoinfoundation/mobilecoin/pull/978
[#979]: https://github.com/mobilecoinfoundation/mobilecoin/pull/979
[#980]: https://github.com/mobilecoinfoundation/mobilecoin/pull/980
[#982]: https://github.com/mobilecoinfoundation/mobilecoin/pull/982
[#983]: https://github.com/mobilecoinfoundation/mobilecoin/pull/983
[#985]: https://github.com/mobilecoinfoundation/mobilecoin/pull/985
[#986]: https://github.com/mobilecoinfoundation/mobilecoin/pull/986
[#988]: https://github.com/mobilecoinfoundation/mobilecoin/pull/988
[#990]: https://github.com/mobilecoinfoundation/mobilecoin/pull/990
[#991]: https://github.com/mobilecoinfoundation/mobilecoin/pull/991
[#992]: https://github.com/mobilecoinfoundation/mobilecoin/pull/992
[#993]: https://github.com/mobilecoinfoundation/mobilecoin/pull/993
[#995]: https://github.com/mobilecoinfoundation/mobilecoin/pull/995
[#996]: https://github.com/mobilecoinfoundation/mobilecoin/pull/996
[#997]: https://github.com/mobilecoinfoundation/mobilecoin/pull/997
[#998]: https://github.com/mobilecoinfoundation/mobilecoin/pull/998
[#999]: https://github.com/mobilecoinfoundation/mobilecoin/pull/999
[#1000]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1000
[#1001]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1001
[#1002]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1002
[#1003]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1003
[#1006]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1006
[#1007]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1007
[#1008]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1008
[#1010]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1010
[#1011]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1011
[#1012]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1012
[#1013]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1013
[#1016]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1016
[#1017]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1017
[#1018]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1018
[#1019]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1019
[#1020]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1020
[#1022]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1022
[#1023]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1023
[#1027]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1027
[#1028]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1028
[#1029]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1029
[#1031]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1031
[#1033]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1033
[#1034]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1034
[#1036]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1036
[#1039]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1039
[#1041]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1041
[#1042]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1042
[#1043]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1043
[#1044]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1044
[#1045]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1045
[#1046]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1046
[#1049]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1049
[#1050]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1050
[#1052]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1052
[#1053]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1053
[#1054]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1054
[#1055]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1055
[#1056]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1056
[#1057]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1057
[#1059]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1059
[#1060]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1060
[#1061]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1061
[#1064]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1064
[#1066]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1066
[#1067]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1067
[#1068]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1068
[#1069]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1069
[#1070]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1070
[#1071]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1071
[#1072]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1072
[#1078]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1078
[#1079]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1079
[#1080]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1080
[#1087]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1087
[#1090]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1090
[#1092]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1092
[#1094]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1094
[#1095]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1095
[#1096]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1096
[#1097]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1097
[#1098]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1098
[#1099]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1099
[#1101]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1101
[#1104]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1104
[#1109]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1109
[#1112]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1112
[#1115]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1115
[#1124]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1124
[#1125]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1125
[#1126]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1126
[#1127]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1127
[#1128]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1128
[#1130]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1130
[#1131]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1131
[#1132]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1132
[#1133]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1133
[#1134]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1134
[#1135]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1135
[#1138]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1138
[#1141]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1141
[#1142]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1142
[#1143]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1143
[#1146]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1146
[#1155]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1155
[#1156]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1156
[#1159]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1159
[#1164]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1164
[#1165]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1165
[#1166]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1166
[#1167]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1167
[#1168]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1168
[#1170]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1170
[#1171]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1171
[#1174]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1174
[#1179]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1179
[#1200]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1200
[#1235]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1235
[#1236]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1236
[#1237]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1237
[#1238]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1238
[#1239]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1239
[#1240]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1240
[#1241]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1241
[#1249]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1249
[#1261]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1261
[#1262]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1262
[#1263]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1263
[#1265]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1265
[#1268]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1268
[#1271]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1271
[#1273]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1273
[#1274]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1274
[#1275]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1275
[#1276]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1276
[#1277]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1277
[#1278]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1278
[#1279]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1279
[#1291]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1291
[#1306]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1306
[#1310]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1310
[#1311]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1311
[#1313]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1313
[#1314]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1314
[#1315]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1315
[#1321]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1321
[#1322]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1322
[#1332]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1332
[#1333]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1333
[#1341]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1341
[#1343]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1343
[#1344]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1344
[#1345]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1345
[#1348]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1348
[#1350]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1350
[#1351]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1351
[#1355]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1355
[#1358]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1358
[#1360]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1360
[#1363]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1363
[#1365]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1365
[#1366]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1366
[#1383]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1383
[#1386]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1386
[#1387]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1387
[#1389]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1389
[#1391]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1391
[#1392]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1392
[#1431]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1431
[#1432]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1432
[#1458]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1458
[#1459]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1459
[#1477]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1477
[#1484]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1484
[#1485]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1485
[#1486]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1486
[#1487]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1487
[#1488]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1488
[#1489]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1489
[#1492]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1492
[#1497]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1497
[#1498]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1498
[#1499]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1499
[#1500]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1500
[#1501]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1501
[#1502]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1502
[#1509]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1509
[#1512]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1512
[#1520]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1520
[#1524]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1524
[#1525]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1525
[#1528]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1528
[#1529]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1529
[#1531]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1531
[#1532]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1532
[#1541]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1541
[#1556]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1556
[#1563]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1563
[#1576]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1576
[#1578]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1578
[#1579]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1579
[#1590]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1590
[#1591]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1591
[#1592]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1592
[#1610]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1610
[#1611]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1611
[#1613]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1613
[#1622]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1622
[#1642]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1642
[#1656]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1656
[#1657]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1657
[#1676]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1676
[#1677]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1677
[#1678]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1678
[#1679]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1679
[#1692]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1692
[#1702]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1702
[#1712]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1712
[#1713]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1713
[#1714]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1714
[#1715]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1715
[#1716]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1716
[#1717]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1717
[#1728]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1728
[#1750]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1750
[#1751]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1751
[#1752]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1752
[#1753]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1753
[#1754]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1754
[#1755]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1755
[#1757]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1757
[#1758]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1758
[#1762]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1762
[#1776]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1776
[#1777]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1777
[#1782]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1782
[#1795]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1795
[#1805]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1805
[#1806]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1806
[#1807]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1807
[#1808]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1808
[#1809]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1809
[#1812]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1812
[#1814]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1814
[#1815]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1815
[#1817]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1817
[#1824]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1824
[#1825]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1825
[#1826]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1826
[#1836]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1836
[#1837]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1837
[#1847]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1847
[#1857]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1857
[#1873]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1873
[#1886]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1886
[#1887]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1887
[#1888]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1888
[#1893]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1893
[#1894]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1894
[#1895]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1895
[#1896]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1896
[#1897]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1897
[#1898]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1898
[#1899]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1899
[#1900]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1900
[#1901]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1901
[#1902]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1902
[#1903]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1903
[#1904]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1904
[#1912]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1912
[#1915]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1915
[#1916]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1916
[#1918]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1918
[#1926]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1926
[#1927]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1927
[#1929]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1929
[#1930]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1930
[#1938]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1938
[#1950]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1950
[#1956]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1956
[#1957]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1957
[#1976]: https://github.com/mobilecoinfoundation/mobilecoin/pull/1976
[#2018]: https://github.com/mobilecoinfoundation/mobilecoin/pull/2018

## [1.1.1] - 2021-08-16

### Changed

- Updated TOS.
- Update IP restriction handling in mobilecoind to match TOS.

## [1.1.0] - 2021-06-08

### Added

- Mnemonics-based Key Derivation
- Dynamic Fees [rfcs/#1](https://github.com/mobilecoinfoundation/rfcs/#1)
  - `consensus-service` now takes `--minimum-fee=<picoMOB>` to configure minimum fees (nodes with different fees cannot attest to each other).
  - `mobilecoind`'s `GenerateOptimizationTxRequest` API to takes a user-supplied fee.
- Authenticated fog details in public addresses
- Admin gRPC for `mobilecoind`.
- `mc-slam` load generation utility.
- `mc-sgx-css-dump` SIGSTRUCT (CSS) debug utility.
- `mobilecoind` can send change to a designated subaddress.
- `mobilecoind` support for load balancing (via forked grpcio).
- `mobilecoind` encrypts account key at rest.
- `watcher` app to keep track of Attestation Verification Reports from live machines.

### Changed

- Bump ISV SVN for consensus enclave to 2
- Reduce minimum fee from 10mMOB to 400uMOB
- Parallelize HTTP transaction fetcher
- Optionally seed RNGs for mock attestation signer from `MC_SEED` env.
- Bump rust version to `nightly-2021-03-25`
- Update SGX to 2.13.3.
- Use `AWS_REGION` instead of `?region=`.
- Make enclave errors (to clients/peers) result in `PERMISSION_DENIED` to force reattestation.
- Fog hints now use AES256-GCM

#### Rust Dependencies

- Update `anyhow` to 1.0.39
- Update `arc-swap` to 0.4.8
- Update `arrayvec` to 0.5.2
- Update `backtrace` to 0.3.55
- Update `base64` to 0.12.3
- Update `bigint` to 4.4.3
- Update `blake2` to 0.9.1
- Update `cc` to 1.0.66
- Update `cfg-if` to 1.0.0
- Update `cookie` to 0.14.3
- Update `crossbeam-channel` to 0.5.0
- Update `curve25519-dalek` to 4.0.0-pre.0
- Update `datatest` to 0.6.4
- Update `displaydoc` to 0.2.0
- Update `fs_extra` to 1.2.0
- Update `futures` to 0.3.8
- Update `hmac` to 0.10.1
- Update `indicatif` to 0.15.0
- Update `libc` to 1.0.80
- Update `mockall` to 0.8.3
- Update `once_cell` to 1.5.2
- Update `pem` to 0.8.2
- Update `proc-macro2` to 1.0.24
- Update `proptest` to 0.10.1
- Update `protobuf` to 2.22.1
- Update `rand_core` to 0.6.2
- Update `rand_hc` to 0.3.0
- Update `rand` to 0.8.3
- Update `reqwest` to 0.10.6
- Update `retry` to 1.2.0
- Update `rocket` to 0.4.6
- Update `semver` to 0.11.0
- Update `serde_json` to 1.0.60
- Update `serde` to 1.0.118
- Update `serial_test` to 0.5.0
- Update `sha2` to 0.9.3
- Update `slog-stdlog` to 4.1.0
- Update `slog-term` to 2.6.0
- Update `structopt` to 0.3.21
- Update `syn` to 1.0.45
- Update `tempfile` to 3.2.0
- Update `thiserr` to 1.0.24
- Update `toml` to 0.5.7
- Update `unicode-normalization` to 1.1.17
- Update `version_check` to 0.9.3
- Update `x25519-dalek` to 1.1.0
- Update `zeroize` to 1.2.0

#### Upstream Forks

- Unfork `bulletproofs` to unreleased 2.0.0 from github
- Fork `grpcio` to a 0.6.0 fork that supports cookies
- Fork `aes-gcm` 0.6.0 to support constant-time decrypt results

#### Python Dependencies

- Update `jinja` to 2.11.3
- Update `pygments` to 2.7.4

### Fixed

- Remove unnecessary limits on consensus request concurrency
- Readme fixes (thanks to contributors @hiqua, @petertodd)
- Fix monitor ID instability in `mobilecoind`.
- Normalize fog URL in public addresses before lookup
- Unified rustfmt

### Security

- Make encryption/decryption success able to be used from within a larger constant-time context for `mc-crypto-box`.
- Stricter EPID Pseudonym length test. (IoActive MC-03)

## [1.0.0] - 2020-11-24

Initial release.

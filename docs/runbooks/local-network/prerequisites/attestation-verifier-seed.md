# Attestation Verifier Seed

For this process, you'll want to seed the [build portion of the attest verifier](https://github.com/mobilecoinfoundation/mobilecoin/blob/master/attest/verifier/build.rs). When built in software simulation mode, which we are doing here for testing, the attest verifier will select a random seed unless provided with one during build. Services that are using builds with different seeds are not compatible with each other, and you will likely get an error saying **AttestationFailed**

To generate the seed, we recommend the following command in terminal

```
echo "<your secret phrase>" | sha256sum
```

This will generate something that looks like the following (middle portion redacted in documentation)

```
a948904f2f0f479b8f81976..........c1cd2a1ec0fb85d299a192a447
```

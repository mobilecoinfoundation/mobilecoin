# Trusted Transparent Transactions (T3) API and Connection

# API

The API crate is used to manage the protobuf files that will be used to generate the rust code upon project build.

It also exports the generated files

## Protobuf

### Building

The protobuf files in the repo will automatically build via the build script and end up in the target directory. These do not get checked in to the repo like the protobuf files do.

### Updating

If there is a need to update the protobuf files, you should use the protobuf_update.sh file in this directory.

This will fetch them from buf.build, which requires you to be authenticated via the buf command line application, and overwrite the proto files in api/proto. From there, they next build should update the built files in the target directory.

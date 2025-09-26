# OpenTelemetry wrapper crate

This crate wraps some
[OpenTelemetry](https://github.com/open-telemetry/opentelemetry-rust)
functionality as well as adds a few utility methods to reduce code duplication

## How do I use this?

We are using opentelemtry as the backend for collecting traces and displaying them.

There are two environment variables that affect the exporting of traces:
- `MC_TELEMETRY` - This needs to be set to `1` or `true` in order for traces to
  be exported
- `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT` - this is where your OpenTelemetry
  collector is running. The default value is `127.0.0.1:4317`.

## How do I add tracing to my crate?

The first step is to ensure that the binary you are running is export traces. This is usually done in the `main()` function:
```
    let _tracer = mc_util_telemetry::setup_default_tracer(env!("CARGO_PKG_NAME"))
        .expect("Failed setting telemetry tracer");
```

This sets up the tracer with the default configuration and makes it accessible throughout your application when you call the `tracer!()` macro.

You should then familiarize yourself with OpenTelemetry - see docs [here](https://docs.rs/opentelemetry/latest/opentelemetry/).

Depending on what you are trying to do, you have a few options of creating a trace span:
1. If your trace data is tied to a specific block id (right now all trace data
   is), you should start by looking at `start_block_span`. This function creates
   a new span that has its trace ID set to the block id (also see
   `block_index_to_trace_id`). This trick allows us to group traces from
   different services by the block id, which was the main purpose of introducing
   distributed tracing.
1. If your code is running inside a parent span (e.g. a span that was created by
   `start_block_span`) and you want more granularity (for example to get better
   visibility into sub-tasks of the parent span), you can use
   `tracer::in_span()`. This will automatically set your trace id and parent
   span id.

It is suggested to search the code for the functions mentioned above to see
examples of how they are used.

## When should I add tracing?

This will likely evolve over time, but for now the main purpose of the tracing
setup in its current form is to give us visibility into where time is spent
throughout the life cycle of a single block. As such, if you are adding
operations that are expected to affect block processing times then it is
suggested you include tracing so that if things slow down we could take a look
and see if any if the changes have affected where time is spent in the life of a
block.

For existing services this can be as simple as wrapping some of your new code
inside `tracer::in_span` (if a parent span has already been properly started by
`start_block_span`), or, if not - `start_block_span`.

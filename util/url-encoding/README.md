mc-util-url-encoding
====================

This crate contains facilities for url-encoding a mobilecoin public address.
As extensions, it can include a request amount and a memo, so that it can encode
a payment request as well.

The design goals are:
- Be simple and straightforward. If I'm a fog user, and fog.mobilecoin.org is my
  fog hostname, then the url's hostname is fog.mobilecoin.org. The amount is
  human readable as a query parameter. The memo is human readable as a query parameter.
  This means that if the url appears e.g. in an email, I have some visibility into
  its contents beyond just b58-encoded bytes. If e.g. the `fog-authority-sig` is missing,
  I can see that that query parameter isn't there, which may make it easier to debug
  why a transfer is failing, than if everything were just a b58 blob.
- Be easy to construct using standard url and base64 javascript libraries.
  If a third-party web developer has e.g. the protobuf corresponding to someone's
  public address, following schema in external.proto, they should ideally be able
  to make a well-formed url-encoded payment request without porting libmobilecoin
  rust code to their platform.
- Be easily extensible. If we want to add more fields, we can simply add query parameters.

This is an alternative to the b58-payloads design, with different tradeoffs.
In experiments, it appears that this format is always 10-20% smaller. This is because
the b58-payloads is applying a b64-like encoding, meant for binary data, to data like URLs,
which are not entropy. This causes unnecessary bloat of the encoding, and also makes it less useful
to humans.

Contents
========

A mob url represents:
- A mobilecoin *public address* (see `mc-transaction-core` struct `PublicAddress`).
- Optionally, *an amount* in picomob (u64) requested to be sent to this address
- Optionally, *a memo* (utf-8 string) indicating the reason to send this amount

Specification
=============

The mob URL specified here is formed by starting with the *fog-url*, if any,
as a base. The fog-url type appears in `mc-util-uri`. (fog-url must be valid to
use with grpc, so it does not contain any path or query parameters).
Then, additional items from the public address are added to this url.

Scheme
------

The url *scheme* is `mob` or `insecure-mob`.

- For a fog-url with scheme "fog", the mob-url scheme is "mob".
- For a fog-url with scheme "insecure-fog", the mob-url scheme is "insecure-mob".
- If the fog-url is missing, the mob-url scheme is "mob".

Hostname
--------

- The *hostname* of the mob-url is the hostname of the fog-url.
- If the fog-url is missing, the hostname is empty. So in this case, the mob-url begins `mob:///`.

Path
----

The *path* in the mob-url is `'/'` followed by a base64 encoded string.

The url-safe base-64 encoding is used, per RFC 3548, with `-`, `=`, and `_` characters.
https://tools.ietf.org/html/rfc3548#section-4

The encoded string is the 66-byte sequence formed by concatenating
the 32-byte spend-public-key and the 32-byte view-public key, followed by 2 checksum checksum bytes.

The two checksum bytes are the first two little-endian bytes of CRC-32-IEEE, and the checksum is
computed over the 64 bytes consisting of the spend-public-key and view-public-key.

(This checksum pads the payload up to 66 bytes, a multiple of 3, before base64 encoding, so that
no base64 padding is required.)

Query-parameters
----------------

The `fog-authority-sig` is encoded as a query parameter using the key `'s'`, and the value is
the base-64 encoding of the bytes of the signature. The url-safe base-64 encoding is used, as
with the path. The sig if present is a 64-byte digital signature, described in detail elsewhere.
As with the path, before base64 encoding it, we pad it up to 66 bytes using two bytes of CRC-32-IEEE
checksum.

The `amount` of the payment request, if any, is encoded as a query parameter using the key `'a'`.
The value is the decimal representation of the picomob request amount.

The `memo` of the payment request, if any, is encoded as a query parameter using the key `'m'`.
The value is the human-readable UTF-8 memo text, encoded using `application/x-www-form-urlencoded`.

For the memo, it is not recommended to override the encoding to be something other than UTF-8 as described https://url.spec.whatwg.org/#urlencoded-serializing.

An empty memo string is logically the same as having no memo string.

Fragment
--------

The `fog-report-id`, if any, is encoded in the fragment of the url. This value is a string.

An empty id string is logically the same as having no id string.

(In practice it is expected that this will usually be the empty string and so can be omitted.)

Examples
========

A public address for an account without fog support. This is base-64 encoded Ristretto curve points.

```
mob:///9i_xwzoihbGu5hLthygfLGi7K1sPFDmhPkq3KPmO-2p4kBwRg06ELfa-mMEnlTUT4RYJXUEizCfYB7RRHLgeEWfP
```

A public address for an account with fog support.

```
mob://fog.mobilecoin.com/oGbA6juTWhUdfL6qNMocAGN96wNiZpZegP0TUjKXHEM-GYmM50bLJVeL6NgftIumjt8nwYw7MjEnQT7hCw9bVUgh?s=CQkJCfSo
```

The fog hostname here is `fog.mobilecoin.signal.org` which indicates where to contact the fog report server.

The path contains the base-64 encoded Ristretto curve points.

The query parameter `?s=...` encodes the user's signature over the fog authority key for `fog.mobilecoin.signal.org`.

A payment request for an account with fog support

```
mob://fog.diogenes.mobilecoin.com/krmSAg7MnM0fn-yTIjV6tHtRA7Zj2JRZ4pJ-_PcweTkAu7afknATa5hFwtc_Zvi8R6d36cnpMA0-inMbZHiqMRqp?a=666&m=2+baby+goats&s=CQkJCfSo
```

The fog hostname here is `fog.diogenes.mobilecoin.com`.

The query parameter `a=666` indicates that the amount is for 666 picomob.
The query parameter `m=2+baby+goats` indicates that the payment is for 2 baby goats.

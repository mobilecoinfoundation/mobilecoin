# Payload encodings for information exchange using deep links.

MobileCoin is designed for use in mobile applications without compromising privacy or security. Funds are controlled by two 32 byte keys: the "spend" and "view" keys. These sixty-four bytes of private user identity can be derived from thirty-two bytes of seed entropy using a key derivation function, but the corresponding public keys are incompressible to less than 64 bytes. When a fog service is in use, a user's public identity will also include instructions for creating the fog hint. Communicating long public address values presents a UX challenge. 

Deep links, collected from a scanned QR code or a followed hyperlink, provide a useful way for users to import tens of bytes, in order to receive an address or payment instructions, or as part of a wallet restoration work flow. To support interoperability between apps, exchanges, and merchant payment processors, MobileCoin has developed payment information encoding schemes as outlined in this crate.

## Payload Types

|Type   | Enum Value | Usage |
|:---------:|:------:|---------|
|Request     |`0x00`|used to allow a client to send a payment, for deposits and purchases from a mobile app|
|Transfer    |`0x01`|used to allow a client to construct a self-payment, for withdrawals to a mobile app|
|Wallet      |`0x02`|used to store partial private keys with checksum information for backup|
|Envelope    |`0x03`|used to share 32 byte private keys for gift card applications|

### Request Payload

When making a deposit to an exchange or at an ATM, or when making a purchase, the payment sender must collect the recipient's `PublicAddress`. A *request payload* can be prepared by the recipient to communicate all of the information the sender requires to complete a transaction. 

The *request payload* format is a base58 encoded byte array, with bytes:

|bytes|min. vers.| description|
|-|-|-|
|`[0..4]      `|0 |little-endian IEEE CRC32 checksum of payload bytes `[4..]`|
|`[4]         `|0 |type (Request = `0x00`)|
|`[5]         `|0 |version (< 256)|
|`[6..38]     `|0 |public view key bytes `[0..32]`|
|`[38..70]    `|0 |public spend key bytes `[0..32]`|
|`[70]        `|1 |length of fog service URL (`f < 256`)|
|`[71..F=(71+f)]  `|1 |fog service URL as utf-8 encoded string (< 256 bytes)|
|`[F..F+8]        `|2 |u64 picoMOB value requested|
|`[F+8]        `|3 |length of memo (`m < 256`)|
|`[F+9..M=(F+9+m)]  `|3 |memo as utf-8 encoded string (< 256 bytes)|
|`[M..]`    |4+ |future version data|

### Transfer Payload

When providing funds for a withdrawal from a cryptocurrency exchange or at an ATM, or to send funds to a recipient who is unable or unwilling to share their public address details, the sender can first move the value to be transfered to a utxo owned by a randomly-generated "transfer account" that is not intended for reuse. The information needed to control the balance of the "transfer account" can be communicated using a *transfer payload*. The recipient of the funds can use the information to construct a self-payment to their own account to complete the withdrawal.

The *transfer payload* format is a base58-encoded byte array, with bytes:

|bytes|min. vers.| description|
|-|-|-|
|`[0..4]      `|0 |little-endian IEEE CRC32 checksum of payload bytes `[4..]`|
|`[4]         `|0 |type (Transfer = 0x01)|
|`[5]         `|0 |version (< 256)|
|`[6..38]     `|0 |seed entropy bytes `[0..32]`|
|`[38..70]    `|0 |utxo identifier bytes `[0..32]`|
|`[70]        `|1 |length of memo (`m < 256`)|
|`[71..M=(71+f)]  `|1 |memo as utf-8 encoded string (< 256 bytes)|
|`[M..]    `|2+ |future version data|

### Wallet Payload

To recover an account generated using our `AccountIdentity` derivation method, a user must supply 32 bytes of seed entropy and the URL for the fog service in use (if any). To improve security, the *wallet payload* stores only 27 bytes of this entropy and asks the user to provide the other 5 bytes as a (random) passphrase. The reconstructed 32 byte seed entropy is then verified using the result of a slow hash function. To avoid transcription errors, we suggest the 5 bytes (i.e. 40 bits) of user-provided seed entropy be represented as a base-32 string of 8 characters. This crate provides utility functions for manipulating the base-32 string passphrase as part of a wallet recovery work flow.

The *wallet payload* format is a base58-encoded byte array, with bytes:

|bytes|min. vers.| description|
|-|-|-|
|`[0..4]      `|0 |little-endian IEEE CRC32 checksum of payload bytes `[4..]`|
|`[4]         `|0 |type (Wallet = 0x02)|
|`[5]         `|0 |version (< 256)|
|`[6..14]     `|0 |slow hash checksum result (based on Argon2i) `[0..8]`|
|`[14..41]    `|0 |truncated seed entropy bytes `[0..27]`|
|`[41..44]    `|1 |a three byte alias code, used for emoji representation|
|`[44]        `|2 |length of fog service URL (`f < 256`)|
|`[45..F=(45+f)]  `|2 |fog service URL as utf-8 encoded string (< 256 bytes)|
|`[F..]    `|3+ |future version data|

### Envelope Payload

To create a physical artifact representing control of funds such as a gift certificate, we can supply a complete 32 bytes of seed entropy and a fog service URL using an *envelope payload*.

The *envelope payload* format is a base58-encoded byte array, with bytes:

|bytes|min. vers.| description|
|-|-|-|
|`[0..4]      `|0 |little-endian IEEE CRC32 checksum of payload bytes `[4..]`|
|`[4]         `|0 |type (Envelope = 0x03)|
|`[5]         `|0 |version (< 256)|
|`[6..38]    `|0 |seed entropy bytes `[0..32]`|
|`[38]        `|1 |length of fog service URL (`f < 256`)|
|`[39..F=(39+f)]  `|1 |fog service URL as utf-8 encoded string (< 256 bytes)|
|`[F..]    `|2+ |future version data|

## QR Compatibility

To maximize compatibility with alphanumeric limitations in QR code libraries, we encode all payload data using a base58 symbol representation using an ASCII symbol set. Any additional conversions required for OS libraries are performed as a second step (e.g. conversion to ISO 8859-1 Latin-1 for the iOS AVFoundation framework). The base58 encoding must preserve the encoded bytes, including leading zeros, but does not need to provide a fixed length output. 

Deep links allow the operating system to automatically launch a compatible wallet app when the user scans a QR code displayed in print, at the point of sale, or on a webpage in a desktop browser window. If a QR code is encountered in a mobile browser, it can be rendered as a button so that deep link is accessible without using the camera.

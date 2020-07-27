## mobilecoind-mirror

The `mobilecoind-mirror` crate consists of two standalone executables, that when used together allow for exposing limited, read-only data from a `mobilecoind` instance. As explained below, this allows exposing some data from `mobilecoind` from a machine that does not require any incoming connections from the outside world.

The mirror consists of two sides:
   1) A private side. The private side of the mirror runs alongside `mobilecoind` and forms outgoing connections to both `mobilecoind` and the public side of the mirror. It then proceeds to poll the public side for any requests that should be forwarded to `mobilecoind`, forwards them, and at the next poll opportunity returns any replies. The set of available requests is defined in the [proto API specifications](proto/mobilecoind_mirror_api.proto).
   Note how the private side only forms outgoing connections and does not open any listening ports.
   2) A public side. The public side of the mirror accepts incoming HTTP connections from clients, and poll requests from the private side over GRPC. The client requests are then forwarded over the GRPC channel to the private side, which in turn forwards them to mobilecoind and returns the responses.


### Example usage

In the examples below we assume that mobilecoind, and both the public and private sides are all running on the same machine. In a real-world scenario the public and private sides would run on separate machines. The following TCP ports are in play:
   - 4444: The port mobilecoind listens on for incoming connecitons.
   - 8001: The default port `mobilecoind-mirror-public` listenins on for incoming HTTP client requests.
   - 10080: The default port the mirror uses for GRPC connections.

The first step in running the mobilecoind mirror is to have a mobilecoind instance running, and accessible from where the private side of the mirror would be running. The mobilecoind instance should have a single monitor configured before proceeding further. The reason for this is that the mirror only supports a single monitor. Upon startup of the private side, it would query mobilecoind for a list of monitors and select the one available. If none, or if multiple monitors are available it would error. When multiple monitors are in use, a specific one can be chosen via a command line argument.


Once mobilecoind is running and set up, start the private side of the mirror:

```
cargo run -p mc-mobilecoind-mirror --bin mobilecoind-mirror-private -- --mirror-public-uri insecure-mobilecoind-mirror://127.0.0.1/ --mobilecoind-host localhost:4444`
```

This starts the private side of the mirror, telling it to connect to `mobilecoind` on localhost:4444 and the public side on `127.0.0.1:10080` (10080 is the default port for the `insecure-mobilecoind-mirror` URI scheme).

At this point you would see a bunch of error messages printed as the private side attemps to initiate outgoing GRPC connections to the public side. This is expected since the public side is not running yet.

Now, start the public side of the mirror:

```
cargo run -p mc-mobilecoind-mirror --bin mobilecoind-mirror-public -- --client-listen-uri http://0.0.0.0:8001/ --mirror-listen-uri insecure-mobilecoind-mirror://127.0.0.1/
```

Once started, the private side should no longer show errors and the mirror should be up and running. You can now send client requests, for example - query the genesis block information:

```
$ curl http://localhost:8001/block/0

{"block_id":"e498010ee6a19b4ac9313af43d8274c53d54a1bbc275c06374dbe0095872a6ee","version":0,"parent_id":"0000000000000000000000000000000000000000000000000000000000000000","index":"0","cumulative_txo_count":"10000","contents_hash":"40bffaff21f4825bc36e4598c3346b375fe77ec1c78f15c8a98623c0ba6b1d21"}
```

Query processed block information for a block your monitor has information for:
```
$ curl http://localhost:8001/processed-block/33826/

{"tx_outs":[{"monitor_id":"08b4e048afc793213fae60d6ad69a5cb73e43a0d1ebba1cdaaf008a912acf1c3","subaddress_index":0,"public_key":"0ce630939a15c9314b36323547fe671d3865622f04190c377571f8c94a066700","key_image":"d20b42ad18a31048e69ea50a5136363f84cca3558a06d1d2c7b6e069fbcf5a53","value":"999999999840","direction":"received"},{"monitor_id":"08b4e048afc793213fae60d6ad69a5cb73e43a0d1ebba1cdaaf008a912acf1c3","subaddress_index":0,"public_key":"58292cdd7f2d7c3caf885d9bbeca69f17d2e15fe781fc31eafbdb9506433560d","key_image":"d6716d7c4f038a847b2f106eed62c0ce59c2e0eecfcf1d1da473bd26e9864d58","value":"999999999890","direction":"spent"}]}
```

For supported requests, the response types are identical to the ones used by [mobilecoind-json](../mobilecoind-json).


### TLS between the mirror sides

The GRPC connection between the public and private side of the mirror can optionally be TLS-encrypted. If you wish to use TLS for that, you'll a certificate file and the matching private key for it. For testing purposes you can generate your own self-signed certificate:

```
$ openssl req -x509 -sha256 -nodes -newkey rsa:2048 -days 365 -keyout server.key -out server.crt

Generating a 2048 bit RSA private key
....................+++
.............+++
writing new private key to 'server.key'
-----
You are about to be asked to enter information that will be incorporated
into your certificate request.
What you are about to enter is what is called a Distinguished Name or a DN.
There are quite a few fields but you can leave some blank
For some fields there will be a default value,
If you enter '.', the field will be left blank.
-----
Country Name (2 letter code) []:US
State or Province Name (full name) []:California
Locality Name (eg, city) []:San Francisco
Organization Name (eg, company) []:My Test Company
Organizational Unit Name (eg, section) []:Test Unit
Common Name (eg, fully qualified host name) []:localhost
Email Address []:test@test.com
```

Note that the `Common Name` needs to match the hostname which you would be using to connect to the public side (that has the GRPC listening port).

After the certificate has been geneerated, you can start the public side of the mirror and instruct it to listen using TLS:
```
cargo run -p mc-mobilecoind-mirror --bin mobilecoind-mirror-public -- --client-listen-uri http://0.0.0.0:8001/ --mirror-listen-uri 'mobilecoind-mirror://127.0.0.1/?tls-chain=server.crt&tls-key=server.key'
```

Notice that the `mirror-listen-uri` has been changed from `insecure-mobilecoind-mirror` to `mobilecoind-mirror`, and that it now contains a `tls-chain` and `tls-key` parameters pointing at the certificate chain file and the matching private key file. The default port for the `mobilecoind-mirror` scheme is 10043.

The private side of the bridge also needs to be aware that TLS is now used:
```
cargo run -p mc-mobilecoind-mirror --bin mobilecoind-mirror-private -- --mirror-public-uri 'mobilecoind-mirror://localhost/?ca-bundle=server.crt' --mobilecoind-host localhost:4444
```

Notice that the `mirror-public-uri` parameter has changed to reflect the TLS certificate chain.


### TLS between the public side of the mirror and its HTTP clients.

Currently, due to `ring` crate version conflicts, it is is not possible to enable the `tls` feature on `rocket` (the HTTP serer used by `mc-mobilecoind-mirror-public`). If you want to provide TLS encryption for clients, you would need to put `mc-mobilecoind-mirror-public` behind a reverse proxy such as `nginx` and have that take care of your TLS needs.

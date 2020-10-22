## Python bindings for the `mobilecoind` API

You must separately install and run `mobilecoind`.

See https://github.com/mobilecoinfoundation/mobilecoin/ for details.

### Example

``` python
import mobilecoin

mobilecoind_address = "localhost:4444"
use_ssl = False

mobilecoind = Client(mobilecoind_address, use_ssl)

print(mobilecoind.get_ledger_info())
```

### Running Package Tests

From the package directory:

```
pip3 install nose
python3 -m nose
```


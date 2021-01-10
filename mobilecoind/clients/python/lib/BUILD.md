## Building and deploying the [`mobilecoin` python package](https://pypi.org/project/mobilecoin/)

### Resources

[PyPi Tutorials](https://packaging.python.org/tutorials/)
[Setup Tool Docs](https://setuptools.readthedocs.io/en/latest/setuptools.html#developer-s-guide)

### Set the PyPi API key

Create the file `~/.pypirc` with content:
```
[distutils]
index-servers =
    pypi

[pypi]
  username = __token__
  password = << token created at pypi account page >>
```
### Compile, package, and deploy

from `./lib/mobilecoin`

1. run `compile_proto.sh`
1. `sed -i -E 's/^import.*_pb2/from . \0/' *.py` or manually edit files, changing all `import *_pb2` to `from . import *_pb2`

from `./lib`

1. bump version in setup.py
1. `python3 setup.py sdist bdist_wheel`
1. `python3 -m twine upload --repository pypi dist/*`

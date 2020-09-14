## Building and deploying the [`mobilecoin` python package](https://pypi.org/project/mobilecoin/)

### Resources

[PyPi Tutorials](https://packaging.python.org/tutorials/)
[Setup Tool Docs](https://setuptools.readthedocs.io/en/latest/setuptools.html#developer-s-guide)

### API Key

Create a the file `~/.pypirc`
```
[distutils]
index-servers =
    pypi

[pypi]
  username = __token__
  password = << token created at pypi account page >>
```

### Package and deploy

from `./lib`

1. `python3 setup.py sdist bdist_wheel`
1. `python3 -m twine upload --repository pypi dist/*`

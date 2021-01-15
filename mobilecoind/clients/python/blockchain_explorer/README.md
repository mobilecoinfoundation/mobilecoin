blockchain_explorer
=====

Quick start:

```
pip3 install -r requirements.txt
python3 blockchain_explorer.py --mobilecoind_host localhost --mobilecoind_port 4444 --port 5000
```

Go to localhost:5000 in a browser to interact.

This can also be run as a flask app:

```
pip3 install -r requirements.txt
export FLASK_APP=blockchain_explorer.py
flask run
```

## Intro

This directory contains a simple Python-based (Flash) tool that can be used to view SCP debug dumps that are generated when the `--scp-debug-dump` flag is passed to `consensus-service`.
Currently, only slot state viewing is implemented.

To use this you would need to grab a copy of the SCP debug dump directory from one or more nodes, and then:
1. Create a Python virtual env: `python3 -m venv env`
1. Activate it: `. ./env/bin/activate`
1. Install dependencies: `pip install -r requirements.txt`
1. Start the web server: `FLASK_ENV=development python viewer.py <directory containing SCP dump files>`
1. Point a browser at http://127.0.0.1:5000/ and begin exploring.

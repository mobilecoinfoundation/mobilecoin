# Copyright (c) 2018-2022 The MobileCoin Foundation

import json
import os
import subprocess

LISTEN_HOST = os.getenv('LISTEN_HOST', '127.0.0.1')

BASE_INGEST_CLIENT_PORT = 4200
BASE_INGEST_PEER_PORT = 4300
BASE_INGEST_ADMIN_PORT = 4400
BASE_INGEST_ADMIN_HTTP_GATEWAY_PORT = 4500

BASE_VIEW_CLIENT_PORT = 5200
BASE_VIEW_ADMIN_PORT = 5400
BASE_VIEW_ADMIN_HTTP_GATEWAY_PORT = 5500

BASE_REPORT_CLIENT_PORT = 6200
BASE_REPORT_ADMIN_PORT = 6400
BASE_REPORT_ADMIN_HTTP_GATEWAY_PORT = 6500

BASE_LEDGER_CLIENT_PORT = 7200
BASE_LEDGER_ADMIN_PORT = 7400
BASE_LEDGER_ADMIN_HTTP_GATEWAY_PORT = 7500

BASE_NGINX_CLIENT_PORT = 8200

PROJECT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))

IAS_API_KEY = os.getenv('IAS_API_KEY', default='0'*64) # 32 bytes
IAS_SPID = os.getenv('IAS_SPID', default='0'*32) # 16 bytes

FOG_SQL_DATABASE_NAME = 'fog_local'
# Use env.DATABASE_URL if it exists, else use postgres://$PGHOST/fog_local,
# falling back to postgres://localhost/fog_local.
DATABASE_URL_ENV = 'DATABASE_URL=${DATABASE_URL:-postgres://${PGHOST:-localhost}/%s}' % FOG_SQL_DATABASE_NAME


def target_dir(release):
    default_target_dir = os.path.join(PROJECT_DIR, 'target')
    base_target_dir = os.path.abspath(os.getenv('CARGO_TARGET_DIR', default_target_dir))
    return os.path.join(base_target_dir, 'release' if release else 'debug')

# Log a command and then call subprocess.run
def log_and_run_shell(cmd, **kwargs):
    print(cmd)
    return subprocess.run(cmd, shell=True, check=True, **kwargs)

# Log a command and then call subprocess.Popen
def log_and_popen_shell(cmd, **kwargs):
    print(cmd)
    process = subprocess.Popen(cmd, shell=True, **kwargs)
    ret = process.poll()
    if ret is not None:
        raise Exception(f'popen {cmd} returned {ret}')
    return process

def start_admin_http_gateway(gateway_port, admin_port, target_dir):
    cmd = ' '.join([
        'ROCKET_CLI_COLORS=0',
        f'exec {target_dir}/mc-admin-http-gateway',
        f'--listen-host {LISTEN_HOST}',
        f'--listen-port {gateway_port}',
        f'--admin-uri insecure-mca://{LISTEN_HOST}:{admin_port}/',
    ])
    return log_and_popen_shell(cmd)


class FogIngest:
    # Arguments:
    # name: A name for this instance for logging purposes
    # work_dir: A temporary directory
    # ledger_db_path: A path to the ledger_db to use as input
    # client_port: The port to which the ingest client can connect to on grpc
    # peer_port: The port to which peers can make attested connections
    # admin_port: The administrative port
    # admin_http_gateway_port: The admin http port
    # release: True if we should use the release mode binaries
    def __init__(self, name, work_dir, ledger_db_path, client_port, peer_port, admin_port, admin_http_gateway_port, release):
        assert os.path.exists(ledger_db_path)

        self.name = name
        self.work_dir = work_dir
        self.ledger_db_path = ledger_db_path

        self.client_port = client_port
        self.client_listen_url = f"insecure-fog-ingest://{LISTEN_HOST}:{self.client_port}/"

        self.peer_port = peer_port
        self.admin_port = admin_port
        self.admin_http_gateway_port = admin_http_gateway_port

        self.release = release
        self.target_dir = target_dir(self.release)

        self.state_file_path = os.path.join(work_dir, f'ingest-{name}-state-file')
        self.ingest_server_process = None
        self.distribution_process = None
        self.admin_http_gateway_process = None

    def __repr__(self):
        return self.name

    def start(self):
        self.stop()

        print(f'Starting fog ingest {self.name}')
        cmd = ' '.join([
            'MC_LOG=trace',
            DATABASE_URL_ENV,
            f'exec {self.target_dir}/fog_ingest_server',
            f'--ledger-db={self.ledger_db_path}',
            f'--client-listen-uri={self.client_listen_url}',
            f'--peer-listen-uri=insecure-igp://{LISTEN_HOST}:{self.peer_port}/',
            f'--peers=insecure-igp://localhost:{self.peer_port}/',
            f'--ias-api-key={IAS_API_KEY}',
            f'--ias-spid={IAS_SPID}',
            f'--local-node-id localhost:{self.peer_port}',
            f'--state-file {self.state_file_path}',
            f'--admin-listen-uri=insecure-mca://{LISTEN_HOST}:{self.admin_port}/',
        ])
        self.ingest_server_process = log_and_popen_shell(cmd)

        print(f'Starting admin http gateway for fog ingest')
        self.admin_http_gateway_process = start_admin_http_gateway(self.admin_http_gateway_port, self.admin_port, self.target_dir)

    def remove_state_file(self):
        os.remove(self.state_file_path)

    def stop(self):
        if self.ingest_server_process and self.ingest_server_process.poll() is None:
            self.ingest_server_process.terminate()
            self.ingest_server_process = None

        if self.admin_http_gateway_process and self.admin_http_gateway_process.poll() is None:
            self.admin_http_gateway_process.terminate()
            self.admin_http_gateway_process = None

    def run_client_command(self, *args):
        cmd = ' '.join([
            f'exec {self.target_dir}/fog_ingest_client',
            f'--uri insecure-fog-ingest://localhost:{self.client_port}',
            *args,
        ])
        return log_and_run_shell(cmd, stdout=subprocess.PIPE).stdout

    def get_status(self):
        result = self.run_client_command('get-status')
        return json.loads(result)

    def activate(self):
        result = self.run_client_command('activate')
        return json.loads(result)

    def set_pubkey_expiry_window(self, value):
        result = self.run_client_command('set-pubkey-expiry-window', str(value))
        return json.loads(result)

    def set_peers(self, peers):
        result = self.run_client_command('set-peers', *peers)
        return json.loads(result)

    def retire(self):
        result = self.run_client_command('retire')
        return json.loads(result)

    def report_lost_ingress_key(self, lost_key):
        return self.run_client_command(f'report-lost-ingress-key -k "{lost_key}"')

class FogView:
    def __init__(self, name, client_responder_id, client_port, admin_port, admin_http_gateway_port, release):
        self.name = name

        self.client_responder_id = client_responder_id
        self.client_port = client_port
        self.client_listen_url = f'insecure-fog-view://{LISTEN_HOST}:{self.client_port}/'

        self.admin_port = admin_port
        self.admin_http_gateway_port = admin_http_gateway_port

        self.release = release
        self.target_dir = target_dir(self.release)

        self.view_server_process = None
        self.admin_http_gateway_process = None

    def __repr__(self):
        return self.name

    def start(self):
        self.stop()

        print(f'Starting fog view {self.name}')
        cmd = ' '.join([
            DATABASE_URL_ENV,
            f'exec {self.target_dir}/fog_view_server',
            f'--client-listen-uri={self.client_listen_url}',
            f'--client-responder-id={self.client_responder_id}',
            f'--ias-api-key={IAS_API_KEY}',
            f'--ias-spid={IAS_SPID}',
            f'--admin-listen-uri=insecure-mca://{LISTEN_HOST}:{self.admin_port}/',
        ])
        self.view_server_process = log_and_popen_shell(cmd)

        print(f'Starting admin http gateway for fog view')
        self.admin_http_gateway_process = start_admin_http_gateway(self.admin_http_gateway_port, self.admin_port, self.target_dir)

    def stop(self):
        if self.view_server_process and self.view_server_process.poll() is None:
            self.view_server_process.terminate()
            self.view_server_process = None

        if self.admin_http_gateway_process and self.admin_http_gateway_process.poll() is None:
            self.admin_http_gateway_process.terminate()
            self.admin_http_gateway_process = None


class FogReport:
    def __init__(self, name, client_port, admin_port, admin_http_gateway_port, release, chain, key):
        self.name = name
        self.client_port = client_port
        self.client_listen_url = f"insecure-fog://{LISTEN_HOST}:{self.client_port}/"

        self.admin_port = admin_port
        self.admin_http_gateway_port = admin_http_gateway_port

        self.release = release
        self.target_dir = target_dir(self.release)

        self.chain = chain
        self.key = key

        self.report_server_process = None
        self.admin_http_gateway_process = None

    def __repr__(self):
        return self.name

    def start(self):
        self.stop()

        print(f'Starting fog report {self.name}')
        cmd = ' '.join([
            DATABASE_URL_ENV,
            f'exec {self.target_dir}/report_server',
            f'--client-listen-uri={self.client_listen_url}',
            f'--admin-listen-uri=insecure-mca://{LISTEN_HOST}:{self.admin_port}/',
            f'--signing-chain={self.chain}',
            f'--signing-key={self.key}'
        ])
        self.report_server_process = log_and_popen_shell(cmd)

        print(f'Starting admin http gateway for fog report')
        self.admin_http_gateway_process = start_admin_http_gateway(self.admin_http_gateway_port, self.admin_port, self.target_dir)

    def stop(self):
        if self.report_server_process and self.report_server_process.poll() is None:
            self.report_server_process.terminate()
            self.report_server_process = None

        if self.admin_http_gateway_process and self.admin_http_gateway_process.poll() is None:
            self.admin_http_gateway_process.terminate()
            self.admin_http_gateway_process = None


class FogLedger:
    def __init__(self, name, ledger_db_path, client_responder_id, client_port, admin_port, admin_http_gateway_port, release):
        self.name = name
        self.ledger_db_path = ledger_db_path

        self.client_responder_id = client_responder_id
        self.client_port = client_port
        self.client_listen_url = f'insecure-fog-ledger://{LISTEN_HOST}:{self.client_port}/'

        self.admin_port = admin_port
        self.admin_http_gateway_port = admin_http_gateway_port

        self.release = release
        self.target_dir = os.path.join(PROJECT_DIR, target_dir(self.release))

        self.ledger_server_process = None
        self.admin_http_gateway_process = None

    def __repr__(self):
        return self.name

    def start(self):
        assert os.path.exists(os.path.join(self.ledger_db_path, 'data.mdb')), self.ledger_db_path
        self.stop()

        print(f'Starting fog ledger {self.name}')
        cmd = ' '.join([
            f'exec {self.target_dir}/ledger_server',
            f'--ledger-db={self.ledger_db_path}',
            f'--client-listen-uri={self.client_listen_url}',
            f'--client-responder-id={self.client_responder_id}',
            f'--ias-api-key={IAS_API_KEY}',
            f'--ias-spid={IAS_SPID}',
            f'--admin-listen-uri=insecure-mca://{LISTEN_HOST}:{self.admin_port}/',
        ])
        self.ledger_server_process = log_and_popen_shell(cmd)

        print(f'Starting admin http gateway for fog ledger')
        self.admin_http_gateway_process = start_admin_http_gateway(self.admin_http_gateway_port, self.admin_port, self.target_dir)

    def stop(self):
        if self.ledger_server_process and self.ledger_server_process.poll() is None:
            self.ledger_server_process.terminate()
            self.ledger_server_process = None

        if self.admin_http_gateway_process and self.admin_http_gateway_process.poll() is None:
            self.admin_http_gateway_process.terminate()
            self.admin_http_gateway_process = None


class FogNginx:
    """Starts a local nginx server that routes requests to the different fog servers"""
    def __init__(self, work_dir, client_port, view_port, ledger_port, report_port):
        self.client_port = client_port
        self.conf_file = os.path.join(work_dir, 'fog-nginx.conf')
        self.nginx_process = None

        # Load the template nginx configuration and search/replace the port numbers
        template = os.path.join(os.path.dirname(__file__), 'fog-nginx.conf')
        template = open(template, 'r').read()
        conf = template.replace(
            'FOG_NGINX_PORT', str(client_port),
        ).replace(
            'FOG_VIEW_PORT', str(view_port),
        ).replace(
            'FOG_LEDGER_PORT', str(ledger_port),
        ).replace(
            'FOG_REPORT_PORT', str(report_port),
        )
        with open(self.conf_file, 'w') as f:
            f.write(conf)

    def start(self):
        assert self.nginx_process is None
        print(f'Starting fog nginx')
        self.nginx_process = log_and_popen_shell(f'nginx -c {self.conf_file}')

    def stop(self):
        if self.nginx_process:
            self.nginx_process.terminate()
            self.nginx_process = None

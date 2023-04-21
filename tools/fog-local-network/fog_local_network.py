# Copyright (c) 2018-2022 The MobileCoin Foundation

import argparse
import os
import subprocess

from local_network import *
from local_fog import *

class FogNetwork(Network):
    def build_binaries(self):
        super().build_binaries()

        enclave_pem = os.path.join(PROJECT_DIR, 'Enclave_private.pem')
        assert os.path.exists(enclave_pem), enclave_pem

        log_and_run_shell(' '.join([
            f'cd {PROJECT_DIR} &&',
            f'CONSENSUS_ENCLAVE_PRIVKEY="{enclave_pem}"',
            f'INGEST_ENCLAVE_PRIVKEY="{enclave_pem}"',
            f'LEDGER_ENCLAVE_PRIVKEY="{enclave_pem}"',
            f'VIEW_ENCLAVE_PRIVKEY="{enclave_pem}"',
            f'cargo build',
            '-p mc-fog-distribution',
            '-p mc-fog-ingest-client',
            '-p mc-fog-ingest-server',
            '-p mc-fog-ledger-server',
            '-p mc-fog-report-server',
            '-p mc-fog-sql-recovery-db',
            '-p mc-fog-test-client',
            '-p mc-fog-view-server',
            f'{CARGO_FLAGS}',
        ]))

    def start(self):
        cmd = ' && '.join([
            f'dropdb --if-exists {FOG_SQL_DATABASE_NAME}',
            f'createdb {FOG_SQL_DATABASE_NAME}',
            f'{DATABASE_URL_ENV} {TARGET_DIR}/fog-sql-recovery-db-migrations',
        ])
        print(f'Creating postgres database: {cmd}')
        subprocess.check_output(cmd, shell=True)

        print("Starting network...")
        super().start()

        print("Starting fog services...")
        try:
            # TODO
            subprocess.check_output("pkill -9 fog_ingest_server 2>/dev/null", shell=True)
        except subprocess.CalledProcessError as exc:
            if exc.returncode != 1:
                raise

        # Directory for fog to store its databases
        fog_work_dir = os.path.join(WORK_DIR, 'fog')
        try:
            os.makedirs(fog_work_dir)
        except:
            pass

        # Get chain and key
        root = subprocess.check_output(f"{TARGET_DIR}/mc-crypto-x509-test-vectors --type=chain --test-name=ok_rsa_head",
                                   encoding='utf8', shell=True).strip()
        chain = subprocess.check_output(f"{TARGET_DIR}/mc-crypto-x509-test-vectors --type=chain --test-name=ok_rsa_chain_25519_leaf",
                                   encoding='utf8', shell=True).strip()
        key = subprocess.check_output(f"{TARGET_DIR}/mc-crypto-x509-test-vectors --type=key --test-name=ok_rsa_chain_25519_leaf",
                                 encoding='utf8', shell=True).strip()
        print(f"chain path = {chain}, key path = {key}")

        # Start fog services
        self.fog_nginx = FogNginx(
            work_dir = fog_work_dir,
            client_port = BASE_NGINX_CLIENT_PORT,
            view_port = BASE_VIEW_CLIENT_PORT,
            ledger_port = BASE_LEDGER_CLIENT_PORT,
            report_port = BASE_REPORT_CLIENT_PORT,
        )
        self.fog_nginx.start()

        self.fog_ingest = FogIngest(
            'ingest1',
            fog_work_dir,
            self.nodes[0].ledger_dir,
            BASE_INGEST_CLIENT_PORT,
            BASE_INGEST_PEER_PORT,
            BASE_INGEST_ADMIN_PORT,
            BASE_INGEST_ADMIN_HTTP_GATEWAY_PORT,
            self.mobilecoind.watcher_db,
            release=True,
        )
        self.fog_ingest.start()

        fog_view_store_1 = FogViewStore(
            name = 'view1',
            client_port = BASE_VIEW_STORE_1_PORT,
            admin_port = BASE_VIEW_STORE_1_ADMIN_PORT,
            admin_http_gateway_port = BASE_VIEW_STORE_1_ADMIN_HTTP_GATEWAY_PORT,
            release = True,
            # Todo: see if we need to reconfigure this...
            sharding_strategy= '0-6'
        )
        fog_view_store_2 = FogViewStore(
            name = 'view2',
            client_port = BASE_VIEW_STORE_2_PORT,
            admin_port = BASE_VIEW_STORE_2_ADMIN_PORT,
            admin_http_gateway_port = BASE_VIEW_STORE_2_ADMIN_HTTP_GATEWAY_PORT,
            release = True,
            # Todo: see if we need to reconfigure this...
            sharding_strategy= '5-12'
        )

        self.fog_view_stores = [fog_view_store_1, fog_view_store_2]
        for store in self.fog_view_stores:
            store.start()
        client_listen_uris = list(map(lambda x: x.get_client_listen_uri(), self.fog_view_stores))

        self.fog_view_router = FogViewRouter(
            name = 'router1',
            client_responder_id = f'localhost:{BASE_NGINX_CLIENT_PORT}',
            client_port = BASE_VIEW_CLIENT_PORT,
            admin_port = BASE_VIEW_ADMIN_PORT,
            admin_http_gateway_port = BASE_VIEW_ADMIN_HTTP_GATEWAY_PORT,
            release = True,
            shard_uris = client_listen_uris
        )
        self.fog_view_router.start()

        self.fog_report = FogReport(
            'report1',
            BASE_REPORT_CLIENT_PORT,
            BASE_REPORT_ADMIN_PORT,
            BASE_REPORT_ADMIN_HTTP_GATEWAY_PORT,
            release=True,
            chain = chain,
            key = key,
        )
        self.fog_report.start()

        self.fog_ledger = FogLedger(
            'ledger1',
            self.nodes[0].ledger_dir,
            f'localhost:{BASE_NGINX_CLIENT_PORT}',
            BASE_LEDGER_CLIENT_PORT,
            BASE_LEDGER_ADMIN_PORT,
            BASE_LEDGER_ADMIN_HTTP_GATEWAY_PORT,
            self.mobilecoind.watcher_db,
            release=True,
        )
        self.fog_ledger.start()

        # Tell the ingest server to activate, giving it a little time for RPC to wakeup
        time.sleep(15)
        cmd = ' '.join([
            f'exec {TARGET_DIR}/fog_ingest_client',
            f'--uri insecure-fog-ingest://localhost:{BASE_INGEST_CLIENT_PORT}',
            f'activate',
        ])
        print(cmd)
        subprocess.check_output(cmd, shell=True)

    def stop(self):
        def stop_server(name):
            server = getattr(self, name, None)
            if server is not None:
                server.stop()

        stop_server("fog_ledger")
        stop_server("fog_report")
        stop_server("fog_view_store_1")
        stop_server("fog_view_store_2")
        stop_server("fog_view_router")
        stop_server("fog_ingest")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Local network tester')
    parser.add_argument('--network-type', help='Type of network to create', required=True)
    parser.add_argument('--skip-build', help='Skip building binaries', action='store_true')
    parser.add_argument('--block-version', help='Set the block version argument', type=int)
    args = parser.parse_args()

    FogNetwork().default_entry_point(args.network_type, args.skip_build, args.block_version)

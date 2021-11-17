# Monitoring

The consensus server exports metrics using [Prometheus](https://prometheus.io). The Prometheus metrics are exposed via the admin service, which is available on port TCP-8000 (as configured in the consensus server container) at the /metrics URL endpoint. These metrics can be scraped by a prometheus server, and graphed using [Grafana](https://grafana.com).

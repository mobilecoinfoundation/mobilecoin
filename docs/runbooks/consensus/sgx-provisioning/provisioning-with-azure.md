# Provisioning with Azure

Azure offers SGX machines through their [Confidential Computing](https://azure.microsoft.com/en-us/solutions/confidential-compute/) platform. Intel is in the process of adding SGX-capable machines in multiple regions and availability zones.

{% hint style="info" %}
You will need to request SGX quota (per core) in specific regions. It can take a few days for quota requests to be fulfilled.
{% endhint %}

Specifications for provisioning with Azure:

| Specification      | Preferred                   | Notes                                                                                                                                                                 |
| ------------------ | --------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Machine Type       | DC4s, DC8s                  | The number refers to the number of cores available. DC2s are also available, but are too underpowered for MobileCoin workloads.                                       |
| Persistent Storage | Premium SSDs                | These are not available in all regions or with all core types. Standard SSD is also acceptable, but may introduce iops bottlenecks.                                   |
| Regions            | <p>West EU,<br>UK South</p> | MobileCoin consensus is slightly latency sensitive, so provisioning in regions somewhat geo-located with existing consensus peers is beneficial to the whole network. |

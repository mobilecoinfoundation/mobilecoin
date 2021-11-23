# FAQs

This section includes some of the most frequently asked questions (FAQs) by node operators:

### **Certs**

Question: Is it possible in general to generate self-signed certs and put their own cert in front of it?

Answer: It is possible to use self-signed certs behind a load-balancer, as long as each consensus node is uniquely addressable by a URI without a path, e.g. mcp://somenode:12345 Platform providers can use a wildcard cert at the load balancer. Currently, MobileCoin nodes operate this way. All nodes connect via TLS to the frontend NGINX ingress, but the nginx ingress then connects back to the nodes in the clear. The cert needs to be pinned internally, so that nginx knows that this cert belongs to this specific host. You will need to share your public keys with every partner and update them when they change.



Question: Can platform providers use a letsencrypt cert that they are already using?

**Answer: You could use a wildcard cert that you already have, but you need a new cert (even if self-signed) for every consensus participant.**

### Intel Attestation Service

Question: Do customers need their own Intel Attestation Service (IAS) Service Provider ID (SPID) key and IAS API Key?

Answer: No. All customers of a provider can use the same IAS SPID and IAS API key.

### **S3**

**Question: Do customers control whether their node pushes blocks to S3?**

Answer: Either way - platform providers can provide an option to provision bucket for ledger distribution (per-org, per customer)

### **TLS Certifications**

**Question: Do all nodes need to have unique TLS certs / can platform providers manage bastion hosts and have insecure connections between nodes internally?**

Answer: All nodes do need to have TLS certs

Question: Is there something specific that has to be in the TLS certs?

Answer: All by DNS and not by IP

**Question: If we renew a cert do we have to restart the node?**

Answer: Yes, because there is a TLS listener inside the nodes

****

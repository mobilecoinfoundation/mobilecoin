# Getting Intel Attestation Service Credentials

The Intel Attestation Service (IAS) credentials allow node operators to register with Intel as Licensed Enclave operators. This credential links the operator identity with the node’s attestation evidence provided to other nodes.&#x20;

**Step 1:** Apply for and obtain an Intel License Agreement to run MobileCoin. Please see: [Partner Intel License Agreement](https://docs.google.com/document/d/1ATv98iLMDlghbC0q8GmbpL6iSlcquy4sVTWAg4nxS6U/edit?usp=sharing).&#x20;

{% hint style="info" %}
Approval can take up to two weeks.
{% endhint %}

**Step 2:** Once your request is approved and the license issued (confirmed via email), you can create your account at the [Intel Trusted Portal](https://api.portal.trustedservices.intel.com) using the email associated with your Partner Intel License Agreement.&#x20;

**Step 3:** Once you log in at the Trusted Portal, this landing page displays. Click on the Intel SGX Attestation Service link to create an EPID subscription.

![The Intel SGX Attestation Service link to create an EPID subscription.](<../.gitbook/assets/intel cert.jpg>)

**Step 4:** After you select the Intel Attestation Service, click on the Subscribe Linkable blue button (under the Production Access section.)

![How to subscribe.](<../.gitbook/assets/subscribe linkable.jpg>)

**Step 5: **Manage your Subscriptions: Click on your username and select Manage Subscriptions to see existing subscriptions. The values of the environment variables are available in this section, as mentioned in Step 6, which are required for the consensus service on start-up.

![Click on Manage Subscriptions to see existing subscriptions.](<../.gitbook/assets/manage subscriptions.jpg>)

{% hint style="info" %}
On this page, you also can navigate to the Analytics Reports, as shown here, of your attestation requests by clicking on the **Analytics reports** button.&#x20;
{% endhint %}

![This analytics report shows the usage and health.](<../.gitbook/assets/analytics reports.jpg>)

**Step 6:** Running the Consensus Server with attestation credentials: Provide the following environment variables when running the consensus service:&#x20;

* IAS\_SPID&#x20;
* IAS\_API\_KEY

The value of both of these values can be found on the Manage Subscriptions \[add a bookmark] page, under your PROD subscription. You can use either the primary or secondary IAS\_API\_KEY interchangeably.&#x20;

You also will need to provide the following environment variables in order to get a successful attestation result:&#x20;

* SGX\_MODE=HW
* IAS\_MODE=PROD

**Step 7:** Verifying attestation results: On start-up, your consensus validator node will attest to the Intel Attestation Service (IAS).&#x20;

The following example log output contains measurement values:

```
2020-09-23 14:08:31.155881673 UTC INFO Measurements: MrEnclave: 
49f3e9e5fbb268ea00c78557fb1bd4efa133555a45de2ea30d3fee04443c79af MrSigner:
bf7fa957a6a94acb588851bc8767e0ca57706c79f4fc2aa6bcb993012c3c386c, mc.enclave_type:
mc_consensus_enclave::ConsensusServiceSgxEnclave, mc.local_node_id:
peer1.prod.mobilecoin.com:443, mc.app: consensus-service, mc.local_node_id:
peer1.prod.mobilecoin.com:443, mc.module: mc_sgx_report_cache_untrusted, mc.src:
sgx/report-cache/untrusted/src/lib.rs:186
```



If your attestation fails, the consensus service will crash.

{% hint style="info" %}
You can see the output of the attestation, if your log level is set to debug, via setting the environment variable RUST\_LOG=debug.
{% endhint %}

The attestation output looks like the following for a SW\_HARDENING\_NEEDED response:

```
2020-09-23 14:08:31.155812272 UTC DEBG Quote verified by remote attestation service// Some code
VerificationReport { sig: VerificationSignature([...]), chain: [[...]], http_body:
"{\"nonce\":\"8c048a88269c9b65afead6485cf637ea\",\"id\":\"2418167485367160266948346
47818919791828\",\"timestamp\":\"2020-09-23T14:08:31.099517\",\"version\":4,\"epidP
seudonym\":\"gKH0dexEpYfuyaGgaKKWmH4VJ8r0L3af1W//p6ya+WaN9BAlSW1Gj3NOWvrQIEAyLCof3f
wS9pkLnZrYk3CXQMSVKQF9q6j4TSTYdC8OicjpaV9nYrAdYWJ9rf3vxtshavmGUP58xTtknFQOxncAsjzn2
maqbm4xhqCrMkzs0fY=\",\"advisoryURL\":\"https://security-center.intel.com\",\"advis
oryIDs\":[\"INTEL-SA-00334\"],\"isvEnclaveQuoteStatus\":\"SW_HARDENING_NEEDED\",\"i
svEnclaveQuoteBody\":\"AgABAMYLAAALAAoAAAAAAL3lg34HPOkq5u/y0l94xuMAAAAAAAAAAAAAAAAA
AAAADw8DBf+ABgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABQAAAAAAAAAHAAA
AAAAAAEnz6eX7smjqAMeFV/sb1O+hM1VaRd4uow0/7gREPHmvAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAC/f6lXpqlKy1iIUbyHZ+DKV3BsefT8Kqa8uZMBLDw4bAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAEAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAABoVXGssD3gYgQ3Gv3zt+rbG9e6ZxZPexmk4vFhAuK0EAYbh4AJHgKTfIWJYeXcJek9l7
rISY1aKIMRzJMqixbn\"}" }..., mc.enclave_type: 
mc_consensus_enclave::ConsensusServiceSgxEnclave, mc.local_node_id: 
peer1.prod.mobilecoin.com:443, mc.app: consensus-service, mc.local_node_id:
peer1.prod.mobilecoin.com:443, mc.module: mc_sgx_report_cache_untrusted, mc.src:
sgx/report-cache/untrusted/src/lib.rs:176
```





&#x20;


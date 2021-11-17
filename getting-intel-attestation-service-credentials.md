# Getting Intel Attestation Service Credentials

The Intel Attestation Service (IAS) credentials allow node operators to register with Intel as Licensed Enclave operators. This credential links the operator identity with the node’s attestation evidence provided to other nodes.&#x20;

**Step 1:** Apply for and obtain an Intel License Agreement to run MobileCoin. Please see: [Partner Intel License Agreement](https://docs.google.com/document/d/1ATv98iLMDlghbC0q8GmbpL6iSlcquy4sVTWAg4nxS6U/edit?usp=sharing).&#x20;

{% hint style="info" %}
Approval can take up to two weeks.
{% endhint %}

**Step 2:** Once your request is approved and the license issued (confirmed via email), you can create your account at the [Intel Trusted Portal](https://api.portal.trustedservices.intel.com) using the email associated with your Partner Intel License Agreement.&#x20;

**Step 3:** Once you log in at the Trusted Portal, this landing page displays. Click on the Intel SGX Attestation Service link to create an EPID subscription.

![The Intel SGX Attestation Service link to create an EPID subscription.](<.gitbook/assets/intel cert.jpg>)

**Step 4:** After you select the Intel Attestation Service, click on the Subscribe Linkable blue button (under the Production Access section.)

![How to subscribe.](<.gitbook/assets/subscribe linkable.jpg>)

**Step 5: **Manage your Subscriptions: Click on your username and select Manage Subscriptions to see existing subscriptions. The values of the environment variables are available in this section, as mentioned in Step 6, which are required for the consensus service on start-up.

![Click on Manage Subscriptions to see existing subscriptions.](<.gitbook/assets/manage subscriptions.jpg>)

{% hint style="info" %}
On this page, you also can navigate to the Analytics Reports, as shown here, of your attestation requests by clicking on the **Analytics reports** button.&#x20;
{% endhint %}

![This analytics report shows the usage and health.](<.gitbook/assets/analytics reports.jpg>)

**Step 6:** Running the Consensus Server with attestation credentials: Provide the following environment variables when running the consensus service:&#x20;

* IAS\_SPID&#x20;
* IAS\_API\_KEY

The value of both of these values can be found on the Manage Subscriptions \[add a bookmark] page, under your PROD subscription. You can use either the primary or secondary IAS\_API\_KEY interchangeably.&#x20;

You also will need to provide the following environment variables in order to get a successful attestation result:&#x20;

* SGX\_MODE=HW
* IAS\_MODE=PROD

**Step 7:** Verifying attestation results: On start-up, your consensus validator node will attest to the Intel Attestation Service (IAS).&#x20;

The following example log output contains measurement values:



&#x20;


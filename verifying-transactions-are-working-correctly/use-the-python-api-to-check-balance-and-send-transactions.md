# Use the Python API to Check Balance and Send Transactions

**Step 1:** Start jupyter notebook.

`jupyter notebook`

**Step 2: **From jupyter, open up [mobilecoind/clients/python/jupyter/wallet.ipynb](https://github.com/mobilecoinofficial/mobilecoin/blob/master/mobilecoind/clients/python/jupyter/wallet.ipynb)

**Step 3: **Connect to the mobilecoind running locally.

{% hint style="info" %}
Screenshots below are taken directly from the jupyter notebook.
{% endhint %}

![How to start the Mob Client](../.gitbook/assets/Start-Mob\_Client1.png)

**Step 4:** Replace the entropy with your entropy.

{% hint style="info" %}
You should receive entropy specific to TestNet that has already been populated with coins.
{% endhint %}

![Input root entropy for account.](../.gitbook/assets/Input\_Root\_Entropy2.png)

**Step 5:** Check balance.

![In the check balance step, you need to provide a subaddress index.](../.gitbook/assets/Monitor\_Your\_Account3.png)

**Step 6:** Generate a Request Code for your account.

![How to generate a public address (request code).](../.gitbook/assets/Public-Address4.png)

**Step 7:** Replace the Request Code in the Send a Transaction Cell with your Request Code and send a transaction.

![How to generate request codes.](../.gitbook/assets/Send\_a\_Transaction6.png)

**Step 8:** Check balance once more to verify that your balance decreased by the minimum fee (10).

![How to check balance for verification.](../.gitbook/assets/Check\_Balance7.png)

{% hint style="info" %}
These Python building blocks can be scripted with your account keys.
{% endhint %}

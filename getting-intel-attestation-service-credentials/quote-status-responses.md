# Quote Status Responses

The isvEnclaveQuoteStatus indicates the Intel Attestation Service’s assessment of the quote.



| isvEnclaveQuoteStatus | Meaning                                                                                                                                                                                                                                                                                                     |
| --------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `OK`                  | The enclave’s configuration is trusted, as associated with the IAS credentials which requested the verification.                                                                                                                                                                                            |
| `SW_HARDENING_NEEDED` | The current enclave is subject to the service advisories provided in the response in the advisoryIDs. The client and peers determine which advisoryIDs they are comfortable with, and proceed to make an attested connection.                                                                               |
| `GROUP_OUT_OF_DATE`   | The enclave’s configuration has expired, likely due to an advisory. The client and peers should not trust a GROUP\_OUT\_OF\_DATE enclave in general. However, depending on the severity of a security advisory, the advisory may still be addressed by MobileCoin enclave developers for a period of time.  |

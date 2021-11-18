# Obtaining the Origin Block

The origin block ships in the container, located at** **`/var/lib/mobilecoin/origin_data/`**.**

You can also obtain the origin block published with each release via S3, for example:

`aws s3 cp s3://mobilecoin.testnet/${BOOTSTRAP_DATE}/${RELEASE_REVISION}/origin-block-data.mdb`

****

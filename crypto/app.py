import os
import boto3
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

s3 = boto3.client("s3")

OUT_BUCKET = os.environ["OUT_BUCKET"]

def handler(event, context):
    record = event["Records"][0]
    in_bucket = record["s3"]["bucket"]["name"]
    in_key = record["s3"]["object"]["key"]

    data = s3.get_object(Bucket=in_bucket, Key=in_key)["Body"].read()

    key = os.urandom(32)
    nonce = os.urandom(12)

    aesgcm = AESGCM(key)
    cipher = aesgcm.encrypt(nonce, data, None)

    s3.put_object(
        Bucket=OUT_BUCKET,
        Key=f"enc/{in_key}.aes",
        Body=cipher,
        Metadata={
            "nonce": nonce.hex(),
            "alg": "AES-256-GCM"
        }
    )

    return {"status": "ok"}

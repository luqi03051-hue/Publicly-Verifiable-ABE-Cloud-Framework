import json
import urllib.parse
import boto3
import os
from datetime import datetime, timezone

s3 = boto3.client("s3")

OUTPUT_BUCKET = os.environ.get("OUTPUT_BUCKET", "demo-output")

def handler(event, context):
    print("Lambda handler invoked")

    rec = event["Records"][0]
    in_bucket = rec["s3"]["bucket"]["name"]
    key = urllib.parse.unquote_plus(rec["s3"]["object"]["key"])

    print(f"bucket={in_bucket}, key={key}")

    obj = s3.get_object(Bucket=in_bucket, Key=key)
    data = obj["Body"].read()

    head = data[:500].decode("utf-8", errors="replace")

    result = {
        "ok": True,
        "input": {"bucket": in_bucket, "key": key, "size": len(data)},
        "file_head_preview": head,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }

    out_key = f"results/{key}.result.json"
    s3.put_object(
        Bucket=OUTPUT_BUCKET,
        Key=out_key,
        Body=json.dumps(result, ensure_ascii=False, indent=2).encode("utf-8"),
        ContentType="application/json"
    )

    print(f"wrote result to s3://{OUTPUT_BUCKET}/{out_key}")

    return {"statusCode": 200, "body": json.dumps({"out_bucket": OUTPUT_BUCKET, "out_key": out_key})}

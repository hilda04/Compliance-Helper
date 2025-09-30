
import os, json, boto3, base64, time

TABLE_NAME = os.environ.get("TABLE_NAME")
BUCKET = os.environ.get("EVIDENCE_BUCKET")

dynamodb = boto3.client("dynamodb")
s3 = boto3.client("s3")

def _resp(status, body):
    return {"statusCode": status, "headers": {"Content-Type": "application/json"}, "body": json.dumps(body)}

def _scan_table():
    items = []
    resp = dynamodb.scan(TableName=TABLE_NAME)
    items.extend(resp.get("Items", []))
    while "LastEvaluatedKey" in resp:
        resp = dynamodb.scan(TableName=TABLE_NAME, ExclusiveStartKey=resp["LastEvaluatedKey"])
        items.extend(resp.get("Items", []))
    out = []
    for it in items:
        out.append({
            "id": it["id"]["S"],
            "createdAt": it["createdAt"]["S"],
            "bucket": it["bucket"]["S"],
            "artifactKey": it["artifactKey"]["S"],
            "artifactHash": it["artifactHash"]["S"],
            "type": it["type"]["S"],
            "controlMappings": json.loads(it["mappings"]["S"]),
        })
    return out

def handler(event, context):
    path = event.get("path", "/")
    method = event.get("httpMethod", "GET")

    if (method == "GET" and path.endswith("/evidence")) or path == "/evidence":
        return _resp(200, _scan_table())

    if method == "POST" and (path.endswith("/export") or path == "/export"):
        body = event.get("body") or "{}"
        if event.get("isBase64Encoded"):
            import base64 as _b64
            body = _b64.b64decode(body).decode()
        data = json.loads(body)
        ids = set(data.get("evidenceIds") or [])
        if not ids:
            return _resp(400, {"error": "Provide evidenceIds: []"})

        items = [it for it in _scan_table() if it["id"] in ids]
        if not items:
            return _resp(404, {"error": "No matching evidence found"})

        manifest_key = f"exports/manifest-{int(time.time())}.json"
        s3.put_object(Bucket=BUCKET, Key=manifest_key, Body=json.dumps(items).encode("utf-8"), ServerSideEncryption="aws:kms")

        url = s3.generate_presigned_url("get_object", Params={"Bucket": BUCKET, "Key": manifest_key}, ExpiresIn=3600)
        return _resp(200, {"exportUrl": url, "count": len(items)})

    return _resp(404, {"error": "Not found"})

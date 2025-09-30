
import os, json, boto3, hashlib, datetime, uuid

EVIDENCE_BUCKET = os.environ.get("EVIDENCE_BUCKET")
TABLE_NAME = os.environ.get("TABLE_NAME")

s3 = boto3.client("s3")
dynamodb = boto3.client("dynamodb")
sts = boto3.client("sts")

def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def _now_iso() -> str:
    return datetime.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"

def _map_controls(bucket_name: str, enc: dict, bpa: dict):
    mappings = []

    # ISO 27001:2022 Annex A examples
    if enc.get("ServerSideEncryptionConfiguration"):
        mappings.append({"framework":"ISO27001", "control":"A.8.24 (Use of cryptography)", "evidence":"SSE configured"})
    else:
        mappings.append({"framework":"ISO27001", "control":"A.8.24", "evidence":"No SSE configured", "status":"gap"})

    if bpa and all(bpa.get(k, {}).get("Value", True) for k in ["BlockPublicAcls","IgnorePublicAcls","BlockPublicPolicy","RestrictPublicBuckets"]):
        mappings.append({"framework":"ISO27001", "control":"A.5.15 (Access control)", "evidence":"Public access blocked"})
    else:
        mappings.append({"framework":"ISO27001", "control":"A.5.15", "evidence":"Public access not fully blocked", "status":"gap"})

    # PCI DSS v4.0 illustrative mapping
    if enc.get("ServerSideEncryptionConfiguration"):
        mappings.append({"framework":"PCI DSS", "control":"3.5.1", "evidence":"Storage encryption enabled"})
    else:
        mappings.append({"framework":"PCI DSS", "control":"3.5.1", "evidence":"No storage encryption", "status":"gap"})

    return mappings

def handler(event, context):
    """Scans S3 buckets; records encryption & public access status as evidence."""
    account = sts.get_caller_identity()["Account"]
    region = os.environ.get("AWS_REGION", "us-east-1")

    resp = s3.list_buckets()
    created = []
    for b in resp.get("Buckets", []):
        name = b["Name"]
        try:
            enc = s3.get_bucket_encryption(Bucket=name)
        except s3.exceptions.ClientError:
            enc = {}

        try:
            bpa = s3.get_public_access_block(Bucket=name)
        except s3.exceptions.ClientError:
            bpa = {}

        evidence = {
            "type": "aws.s3.bucket.posture",
            "account": account,
            "region": region,
            "resource": name,
            "capturedAt": _now_iso(),
            "encryption": enc,
            "publicAccessBlock": bpa,
        }
        mappings = _map_controls(name, enc, bpa)
        evidence["controlMappings"] = mappings

        data = json.dumps(evidence, separators=(",", ":"), sort_keys=True).encode("utf-8")
        digest = _sha256(data)
        evidence_id = str(uuid.uuid4())
        key = f"evidence/{account}/{region}/s3/{name}/{evidence_id}.json"

        s3.put_object(
            Bucket=EVIDENCE_BUCKET,
            Key=key,
            Body=data,
            ServerSideEncryption="aws:kms",
        )

        dynamodb.put_item(
            TableName=TABLE_NAME,
            Item={
                "id": {"S": evidence_id},
                "createdAt": {"S": evidence["capturedAt"]},
                "bucket": {"S": name},
                "artifactKey": {"S": key},
                "artifactHash": {"S": digest},
                "type": {"S": evidence["type"]},
                "mappings": {"S": json.dumps(mappings)},
            }
        )
        created.append({"id": evidence_id, "key": key, "hash": digest})

    return {"statusCode": 200, "body": json.dumps({"created": created})}

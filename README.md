
# Compliance Helper (MVP)

Evidence capture & mapping to ISO/PCI controls for faster audits.

## What this MVP does

- Captures **S3 bucket security posture** (encryption, block-public-access) as evidence.
- Writes evidence JSON to a versioned S3 bucket with SHA256 hash and timestamp.
- Maps evidence to **ISO 27001:2022 Annex A** and **PCI DSS v4.0** using simple rules.
- Exposes a minimal **HTTP API** via API Gateway + Lambda:
  - `GET /evidence` – list evidence items & mappings (from DynamoDB)
  - `POST /export` – build and return a pre-signed URL to a ZIP containing selected evidence + manifest
- Schedules collection via **EventBridge** (default: hourly).

> This is a starter; add more collectors (IAM, KMS, Security Groups, CloudTrail, Config, etc.).

## Quick start

Prereqs: AWS CLI, AWS SAM CLI, Python 3.11+

```bash
# 1) Install deps for local tooling (optional)
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# 2) Configure AWS credentials
aws configure

# 3) Deploy (guided on first run)
sam deploy --guided
```

During the guided deploy you will be asked to provide:
- **EvidenceBucketName**: S3 bucket name for storing evidence artifacts (will be created, versioning & SSE-KMS enabled).
- **KmsAlias**: KMS alias (will be created if it doesn’t exist), e.g. `alias/compliance-helper`.

## API

- `GET /evidence` -> returns array of evidence records (id, bucket, key, hash, timestamp, controlMappings[])
- `POST /export` -> body: `{ "evidenceIds": ["..."] }` -> returns `{ "exportUrl": "https://..." }`

## Extend mapping

Edit **`src/mapper/rules.json`** to add control mappings. The `controlMappings` field is saved into each evidence record.

## Security notes

- Evidence stored with **SSE-KMS** and **S3 Versioning**. You can enable **Object Lock** (WORM) manually in bucket settings if required.
- IAM least-privilege policies are scoped to the evidence bucket and DynamoDB table.
- CloudTrail logs recommended for API and collector role monitoring.

## Testing

```bash
sam build && sam local invoke EvidenceCollectorFunction
sam local start-api  # then curl localhost:3000/evidence
```

---

© 2025, MIT licensed.

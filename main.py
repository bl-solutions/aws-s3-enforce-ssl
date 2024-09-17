import json
from typing import Optional

import boto3
import boto3.session
import botocore.exceptions


MAX_BUCKETS = 100
ENFORCED_SSL_STATEMENT = {
    "Sid": "EnforceSSLRequestsOnly",
    "Effect": "Deny",
    "Principal": "*",
    "Action": "s3:*",
    "Resource": [
        "arn:aws:s3:::{bucket}",
        "arn:aws:s3:::{bucket}/*",
    ],
    "Condition": {"Bool": {"aws:SecureTransport": "false"}},
}


def new_s3_client() -> boto3.session.Session.client:
    """Create a new Boto3 S3 client

    Returns:
        boto3.session.Session.client: Boto3 S3 client
    """
    client = boto3.client("s3")
    return client


def list_buckets(
    client: boto3.session.Session.client, continuation_token: Optional[str] = ""
) -> list[str]:
    """List every S3 bucket name on the account.

    Args:
        client (boto3.session.Session.client): Boto3 client for S3 service
        continuation_token (Optional[str], optional): Continuation token used for API pagination. Defaults to "".

    Returns:
        list[str]: Name of S3 buckets on the account
    """
    response = client.list_buckets(
        MaxBuckets=MAX_BUCKETS,
        ContinuationToken=continuation_token,
    )

    buckets = [bucket["Name"] for bucket in response["Buckets"]]
    continuation_token = response.get("ContinuationToken")

    if continuation_token:
        buckets.extend(list_buckets(client, continuation_token))

    return buckets


def get_bucket_policy(
    client: boto3.session.Session.client, bucket: str
) -> Optional[dict]:
    """Retrieve the bucket policy of a specific bucket.

    Args:
        client (boto3.session.Session.client): Boto3 client for S3 service
        bucket (str): Bucket name

    Returns:
        Optional[dict]: Optional bucket policy. None if there is no bucket policy.
    """
    try:
        response = client.get_bucket_policy(Bucket=bucket)
        policy = json.loads(response["Policy"])
        policy.pop("Id", None)
    except botocore.exceptions.ClientError as e:
        if e.response["Error"]["Code"] == "NoSuchBucketPolicy":
            policy = None
        else:
            print(f"Unexpected error on getting bucket policy for {bucket}")
            exit(1)
    return policy


def is_already_implemented(bucket: str, policy: dict) -> bool:
    """Verify if ENFORCED_SSL_STATEMENT is already implemented on a bucket policy.

    Args:
        bucket (str): Bucket name
        policy (dict): Bucket policy content

    Returns:
        bool: True if the policy is already implemented, False if not
    """
    if not policy:
        return False
    
    enforced_ssl_statement = copy.deepcopy(ENFORCED_SSL_STATEMENT)
    enforced_ssl_statement["Resource"] = [r.format(bucket=bucket) for r in ENFORCED_SSL_STATEMENT["Resource"]]
    enforced_ssl_statement.pop("Sid", None)
    
    policy_statements = copy.deepcopy(policy.get("Statement", []))
    
    for s in policy_statements:
        s.pop("Sid", None)
        if s == enforced_ssl_statement:
            return True
    
    return False


def update_bucket_policy(bucket: str, policy: Optional[dict]) -> str:
    """Update the bucket policy to implement the ENFORCED_SSL_STATEMENT statement.

    Args:
        bucket (str): Bucket name
        policy (Optional[dict]): Bucket policy content

    Returns:
        str: Bucket policy content
    """
    enforced_ssl_statement = ENFORCED_SSL_STATEMENT.copy()
    enforced_ssl_statement["Resource"] = [
        r.format(bucket=bucket) for r in ENFORCED_SSL_STATEMENT["Resource"]
    ]

    if policy:
        updated_policy = policy
        updated_policy["Statement"].append(enforced_ssl_statement)
    else:
        updated_policy = {
            "Version": "2012-10-17",
            "Statement": [enforced_ssl_statement],
        }

    return json.dumps(updated_policy)


def put_bucket_policy(
    client: boto3.session.Session.client, bucket: str, policy: str
) -> None:
    """Put a bucket policy to a specific bucket.

    Args:
        client (boto3.session.Session.client): Boto3 client for S3 service
        bucket (str): Bucket name
        policy (str): Bucket policy content
    """
    client.put_bucket_policy(Bucket=bucket, Policy=policy)


def main():
    client = new_s3_client()
    buckets = list_buckets(client)

    for b in buckets:
        # print(f"Bucket: {b}")
        # print("--- Current policy ---")
        policy = get_bucket_policy(client, b)
        # print(policy)

        # print("--- Updated policy ---")

        if not is_already_implemented(b, policy):
            print(f"❌ {b} is not compliant")
            try:
                updated_policy = update_bucket_policy(b, policy)
                # print(updated_policy)
                # put_bucket_policy(client, b, updated_policy)
                print(f"ℹ️ {b} bucket policy updated")
            except:
                print(f"☠️ failed to update {b} bucket policy")

        else:
            print(f"✔️ {b} is compliant")
            continue


if __name__ == "__main__":
    main()

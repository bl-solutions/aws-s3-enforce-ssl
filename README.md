# aws-s3-enforce-ssl

This script verify if S3 buckets enforce SSL on incoming requests.
It can update the bucket policy to enforce SSL.

## Installation

The script have been tested with Python 3.12.
You have to use this version of Python to run the script.

I recommand to create a virtual environment with your favorite environment tool (conda, virtualenv, etc.).

Then, install the Python required modules: `pip install -r requirements.txt`.

## Usage

The script use the AWS CLI configuration on your host.

You can use a specific profile by setting the `AWS_PROFILE` environment variable. If not set, it use the default profile.

```bash
AWS_PROFILE=<profile-name> python main.py
```

Help message can be displayed with the flags `-h`, `--help`.

### Work on specific buckets

You can specify one or many buckets to use with the `--buckets` flag.

### Update existing bucket policies

By default, the script run in dry-run mode. No changes are applied to the existing bucket policies.

To update existing bucket policies, you need to run the script with `--apply` flag.

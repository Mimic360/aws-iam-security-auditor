import boto3
from dotenv import load_dotenv

# Pull credentials from .env into the environment before boto3 tries to read them
load_dotenv()


def get_iam_client():
    # boto3 automatically picks up AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY,
    # and AWS_DEFAULT_REGION from the environment — no need to pass them manually
    return boto3.client("iam")

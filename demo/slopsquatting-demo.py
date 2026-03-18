"""
Demo file simulating AI-generated code with hallucinated package imports.

This file is used to test the Slopsquatting Detector agent. It contains a mix
of real PyPI packages and phantom (non-existent) packages that an AI code
assistant might hallucinate.
"""

# --- Real packages (exist on PyPI) ---
import requests
import flask
import pandas
from cryptography.fernet import Fernet

# --- Phantom packages (DO NOT exist on PyPI) ---
import fastauth                          # hallucinated auth library
import cloudstoragelib                   # hallucinated cloud storage
from dataprocessorx import transform     # hallucinated data processing
import securevaultpython                 # hallucinated secrets manager
from ailoggingutil import setup_logger   # hallucinated logging wrapper


def main():
    """Example function using the imported packages."""
    # Real usage
    resp = requests.get("https://example.com")
    app = flask.Flask(__name__)
    df = pandas.DataFrame({"col": [1, 2, 3]})
    key = Fernet.generate_key()

    # Hallucinated usage — these would fail at runtime
    auth = fastauth.create_client("my-app")           # noqa: F821
    storage = cloudstoragelib.connect("s3://bucket")   # noqa: F821
    data = transform(df)                                # noqa: F821
    vault = securevaultpython.open("prod-secrets")      # noqa: F821
    logger = setup_logger("app")                        # noqa: F821

    return resp, app, df, key, auth, storage, data, vault, logger


if __name__ == "__main__":
    main()

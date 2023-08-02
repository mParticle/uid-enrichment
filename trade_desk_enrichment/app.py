import base64
import json
import logging
import os
import time
import uuid

import certifi
from Crypto.Cipher import AES
from requests.packages.urllib3.util.retry import Retry
from urllib3 import PoolManager, exceptions

log_level = os.getenv('LogLevel')
mp_env = os.getenv('mParticleEnvironment')
mP_feed_key = os.getenv('mParticleFeedKey')
mP_feed_secret = os.getenv('mParticleFeedSecret')
uid_key = os.getenv('UIDKey')
uid_secret = os.getenv('UIDSecret')
uid_url = os.getenv('UIDURL')
event_name = os.getenv('EVENT_NAME')

logging.basicConfig(level=log_level)


def encrypt_request(secret: str, email: str):
    """
    This function will accept a secret and an email and build a request to trade-desk per the spec's defined
    here: https://github.com/UnifiedID2/uid2docs/blob/main/api/v2/encryption-decryption.md#encrypting-requests
    :param secret: Secret to retrieve UID2.0 from a public or private operator
    :param email: Email or list of emails to retrieve the raw UID2.0 values for
    :return: Encrypted request to be sent to trade-desk
    """

    # Secret key and payload
    secret = base64.b64decode(secret)
    payload = f'{{"email": ["{email}"]}}'

    # Random 12 byte initialization vector
    iv = os.urandom(12)
    cipher = AES.new(secret, AES.MODE_GCM, nonce=iv)
    time_milliseconds = int(time.time() * 1000)
    nonce = os.urandom(8)

    # Construct a request body
    body = bytearray(time_milliseconds.to_bytes(8, 'big'))
    body += bytearray(nonce)
    body += bytearray(bytes(payload, 'utf-8'))
    ciphertext, tag = cipher.encrypt_and_digest(body)
    # version of the envelope format
    envelope = bytearray(b'\x01')
    # 96 digit initialization vector, to randomize data encryption
    envelope += bytearray(iv)
    # Payload encrypted using AES/GCM/NO Padding algorithm
    envelope += bytearray(ciphertext)
    # 128 big authentication tage to verify data integrity
    envelope += bytearray(tag)

    return base64.b64encode(bytes(envelope)).decode()


def ttd_connector(api_key: str, payload: str, uid_url: str):
    """
    This function accepts an API Key and pay load to make a request to TTD and returns the status
    :param api_key: API Key to retrieve UID2.0 from a public or private operator
    :param payload: Encrypted payload
    :return: status
    """
    retry_strategy = Retry(
        total=5,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["GET", "POST"],
        # {backoff factor} * (2 ** ({number of total retries} - 1))
        backoff_factor=1
    )
    http = PoolManager(num_pools=2, retries=retry_strategy, ca_certs=certifi.where())
    headers = {
        'Authorization': f"Bearer {api_key}",
    }
    try:
        response = http.request('POST', url=uid_url, body=payload, headers=headers)
        if response.status == 200:
            return {"status": "success", "response_body": response.data.decode('utf-8'), "status_code": 200}
        if response.status == 401:
            return {"status": "Invalid UID Credentials", "status_code": 401}
        else:
            return {"status": "Error from UID Service", "status_code": 500}
    except Exception as error:
        logging.debug(error)
        return {"status": "error", "message": error, "status_code": 500}
    except exceptions.MaxRetryError as error:
        logging.debug(error)
        return {"status": "error", "status_code": 500}


def decrypt_request(secret: str, response: str):
    """
    This function will accept a secret and decrypt the response per the spec's defined
    here: https://github.com/UnifiedID2/uid2docs/blob/main/api/v2/encryption-decryption.md#decrypting-responses
    :param secret: Secret to retrieve UID2.0 from a public or private operator
    :param response: Response string from UID API
    :return: advertising_id and email
    """
    secret = base64.b64decode(secret)
    response_bytes = base64.b64decode(response)
    iv = response_bytes[:12]
    data = response_bytes[12:len(response_bytes) - 16]
    tag = response_bytes[len(response_bytes) - 16:]
    cipher = AES.new(secret, AES.MODE_GCM, nonce=iv)
    decrypted_response = cipher.decrypt_and_verify(data, tag)
    json_response = json.loads(decrypted_response[16:].decode('utf-8'))
    email = json_response.get('body').get('mapped')[0].get('identifier')
    advertising_id = json_response.get('body').get('mapped')[0].get('advertising_id')
    return {"email": email, "advertising_id": advertising_id, "status_code": 200}


def mparticle_connector(feed_key: str, feed_secret: str, advertising_id: str, email: str, ):
    """
    This function loads the user UID token as other ID in mParticle and a custom event
    :param email: User's email
    :param advertising_id: User's advertising_id token
    :param feed_key: Customer Feed Key
    :param feed_secret: Customer Feed Secret
    :param event_name: Custom Event name
    :return: status
    """
    retry_strategy = Retry(
        total=5,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["GET", "POST"],
        # {backoff factor} * (2 ** ({number of total retries} - 1))
        backoff_factor=1
    )
    api_key = f'{feed_key}:{feed_secret}'
    encoded_api_key = base64.b64encode(api_key.encode())
    authentication_key = encoded_api_key.decode()
    http = PoolManager(num_pools=2, retries=retry_strategy, ca_certs=certifi.where())
    headers = {
        'Authorization': f"Basic {authentication_key}",
        'Content-Type': 'application/json'
    }
    request_body = json.dumps({
        "events": [
            {
                "data": {
                    "event_name": event_name,
                    "custom_event_type": "other",
                    "source_message_id": str(uuid.uuid4())
                },
                "event_type": "custom_event"
            }
        ],
        "partner_identities": {
            "ttd_uid2": advertising_id
        },
        "user_identities": {
            "email": email,

        },
        "environment": mp_env
    })
    try:
        response = http.request('POST', url='https://s2s.mparticle.com/v2/events', body=request_body, headers=headers)
        if response.status == 202:
            return {"status": "success", "status_code": 202}
        if response.status == 401:
            return {"status": "Invalid Feed Credentials", "status_code": 401}
    except Exception as error:
        logging.debug(error)
        return {"status": "error", "message": error, "status_code": 500}
    except exceptions.MaxRetryError as error:
        logging.debug(error)
        return {"status": "error", "status_code": 500}


def lambda_handler(event: dict, context: dict):
    print(json.dumps(event))
    """
    :param event: Event from mParticle Audience Engine
    :param context: Context from the lambda invocation
    :return: Status code for the operation
    """

    # Accept new audience connection requests:
    event_body = json.loads(event.get('body'))

    logging.debug(event_body)
    if event_body.get('type') == 'audience_subscription_request':
        return json.dumps({
            "type": "audience_subscription_response",
            "id": str(uuid.uuid4()),
            "timestamp_ms": round(time.time()),
            "firehose_version": "2.8.0",
        })
    # Process the change requests
    # Handle Verification requests
    user_profiles = event_body.get('user_profiles')
    if user_profiles is None:
        return json.dumps({
            "type": "audience_membership_change_response",
            "id": str(uuid.uuid4()),
            "timestamp_ms": round(time.time()),
            "firehose_version": "2.8.0",
            "suspend_subscription": False

        })

    # Parse out the credentials from the request
    api_key = event_body.get('account').get('account_settings').get('uidKey')
    api_secret = event_body.get('account').get('account_settings').get('uidSecret')
    feed_key = event_body.get('account').get('account_settings').get('feedKey')
    feed_secret = event_body.get('account').get('account_settings').get('feedSecret')
    for user_identities in user_profiles:
        for i in (user_identities.get('user_identities')):
            if i.get('type') == 'email':
                # get the users email
                user_email = i.get('value')
                # Encrypt users email
                encrypted_payload = encrypt_request(api_secret, user_email)
                # Request UID for the user
                ttd_response = ttd_connector(api_key, encrypted_payload, uid_url)
                # If there is a successful response from TTD, decrypt the response
                if ttd_response.get('status_code') == 200:
                    encrypted_response = ttd_response.get('response_body')
                    decrypted_response = decrypt_request(api_secret, encrypted_response)
                    # If the decryption is successful,parse out email and UID
                    if decrypted_response.get('status_code') == 200:
                        email = decrypted_response.get('email')
                        uid = decrypted_response.get('advertising_id')
                        # Upload to mParticle
                        mp_response = mparticle_connector(feed_key, feed_secret, uid, email)
                        logging.debug(mp_response)

    return json.dumps(
        {
            "type": "audience_membership_change_response",
            "id": str(uuid.uuid4()),
            "timestamp_ms": round(time.time()),
            "firehose_version": "2.8.0",
            "suspend_subscription": False

        }
    )

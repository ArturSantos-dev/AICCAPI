import hashlib
import hmac
import urllib.parse
from datetime import datetime, timezone
import base64
import requests  # Ensure you have requests installed: pip install requests


def normalize(value):
    """
    Percent-encode a string, excluding unreserved characters.
    """
    return urllib.parse.quote(value, safe='-._~')


def format_timestamp(timestamp):
    """
    Format the timestamp as 'yyyy-MM-dd'T'HH:mm:ss.SSS'Z''.
    """
    return timestamp.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'


def hmac_sha256(key, msg):
    """
    Compute HMAC-SHA256 and return the raw bytes.
    """
    if isinstance(key, str):
        key = key.encode('utf-8')
    return hmac.new(key, msg.encode('utf-8'), hashlib.sha256).digest()


def build_canonical_query_string(query_parameters):
    """
    Build the canonical query string by normalizing and sorting the query parameters.
    """
    if not query_parameters:
        return ''
    # Sort the query parameters alphabetically
    sorted_params = sorted((normalize(k), normalize(v)) for k, v in query_parameters.items())
    # Concatenate the sorted parameters
    canonical_query_string = '&'.join(f"{k}={v}" for k, v in sorted_params)
    return canonical_query_string


def build_canonical_request(http_method, uri, query_parameters, signed_headers, canonical_headers, payload):
    """
    Construct the CanonicalRequest string.
    """
    cr = [http_method, '\n', uri, '\n']

    # Canonical query string
    canonical_query_string = build_canonical_query_string(query_parameters)
    cr.append(canonical_query_string)
    cr.append('\n')

    # Signed headers
    cr.append(';'.join(signed_headers))
    cr.append('\n')

    # Canonical headers
    for header_name in signed_headers:
        header_value = canonical_headers[header_name]
        cr.append(f'{header_name}:{header_value}\n')
    cr.append('\n')

    # Normalized payload
    normalized_payload = normalize(payload)
    cr.append(normalized_payload)

    return ''.join(cr)


def main():
    # Inputs
    access_key = "globalaktest"
    secret_key = "1qaz2wsx3edc4rfv5tgb6yhn7ujm8ik9ol0p"
    host = "10.22.26.181:28080"
    uri = "/rest/cmsapp/v1/ping"
    http_method = "POST"
    timestamp = datetime.now(timezone.utc)
    formatted_timestamp = format_timestamp(timestamp)
    payload = '{"say": "Hello world!"}'

    # Example query parameters (if any)
    query_parameters = {
        # 'param1': 'value1',
        # 'param2': 'value2',
    }

    # Compute Content-Length
    content_length = str(len(payload.encode('utf-8')))

    # Construct headers
    headers = {
        'host': host,
        'content-length': content_length,
        'content-type': 'application/json;charset=UTF-8'
    }

    # Lowercase and sort header names
    signed_headers = sorted([k.lower() for k in headers.keys()])

    # Canonical headers with normalized values
    canonical_headers = {}
    for k in signed_headers:
        v = headers[k]
        normalized_value = normalize(v.strip())
        canonical_headers[k] = normalized_value

    # Build CanonicalRequest
    canonical_request = build_canonical_request(
        http_method, uri, query_parameters, signed_headers, canonical_headers, payload
    )

    # Build authStringPrefix
    auth_version = "auth-v2"
    signed_headers_str = ';'.join(signed_headers)
    auth_string_prefix = f"{auth_version}/{access_key}/{formatted_timestamp}/{signed_headers_str}"

    # Compute SigningKey (raw bytes)
    signing_key = hmac_sha256(secret_key, auth_string_prefix)

    # Compute Signature (raw bytes)
    signature_digest = hmac_sha256(signing_key, canonical_request)

    # Base64-encode the signature
    signature = base64.b64encode(signature_digest).decode('utf-8')

    # Build Authorization header
    authorization = f"{auth_string_prefix}/{signature}"

    # Construct final headers for the request
    request_headers = {
        'Authorization': authorization,
        'Host': headers['host'],
        'Content-Length': headers['content-length'],
        'Content-Type': headers['content-type'],
    }

    # Define the proxy (replace with your proxy details)
    proxies = {
        'http': 'http://proxy.example.com:8080',  # Replace with your proxy URL
        'https': 'http://proxy.example.com:8080',  # Replace with your proxy URL
    }

    # Prepare the full URL
    url = f"https://{host}{uri}"

    # Send the HTTP POST request through the proxy
    response = requests.post(
        url,
        headers=request_headers,
        data=payload,
        proxies=proxies,
        verify=False,  # Set to True in production
        timeout=30
    )

    # Print the response
    print("\nResponse Status Code:")
    print(response.status_code)
    print("\nResponse Headers:")
    for k, v in response.headers.items():
        print(f"{k}: {v}")
    print("\nResponse Body:")
    print(response.text)


if __name__ == "__main__":
    main()

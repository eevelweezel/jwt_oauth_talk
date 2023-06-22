import base64
from datetime import (
    datetime,
    timedelta,
    timezone,
)
import json

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.serialization import load_pem_private_key

# load keypair from file
private_key = None
with open('keypair.pem', 'rb') as keyfile:
    private_key = load_pem_private_key(
                      keyfile.read(),
                      password=None,
    )

public_key = private_key.public_key()

# assemble headers (no kid, as we're *just* building a token)
headers = json.dumps({'alg': 'RS256', 'typ': 'JWT'}, default=str).encode('utf-8')

# assemble claims
claims = {
   'exp': datetime.now(tz=timezone.utc) + timedelta(hours=1),
   'alg': 'RS256',
   'iss': 'me',
   'iat': datetime.now(tz=timezone.utc),
   'nbf': datetime.now(tz=timezone.utc),
   'aud': ['me', 'you'],
}

# serialize and encode the claims
payload = json.dumps(claims,default=str).encode('utf-8')

# base64 encode & stringify the header and claims
# start assembling the token string
token_string = base64.urlsafe_b64encode(headers).decode('utf-8') + '.' + base64.urlsafe_b64encode(payload).decode('utf-8')

# generate the cryptographic signature
sig = private_key.sign(
    token_string.encode('utf-8'),
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH,
    ),
    hashes.SHA256(),
)

# decode signature & strip padding, then append resulting string to token
token = token_string + '.' + base64.urlsafe_b64encode(sig).decode('utf-8').strip('=')
print(f'Generated token is {token}\n\n')

# To retrieve the contents, we split on '.', re-encode the strings, then b64decode them.

hd, cl, sg = token.split('.')

hd_decoded = base64.urlsafe_b64decode(bytes(hd, encoding='utf-8'))
print(f'decoded bytes {hd_decoded}')

cl_decoded = base64.urlsafe_b64decode(bytes(cl, encoding='utf-8'))
print(f'decoded claims {cl_decoded}')

# Now, we should verify the claims and signature. I'm not doing that here, you get the point. There is a much easier way.

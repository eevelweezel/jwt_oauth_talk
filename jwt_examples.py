from datetime import (
    datetime,
    timedelta,
    timezone,
)

import jwt


"""
You need to read keys from file either way. There's this strategy,
which uses separate files, or the example from the previous example.
Both work. The cryptography library is a low-level dependency of pyjwt.
"""

# load keys
pubkey = None
with open('publickey.crt', 'r') as keyfile:
    pubkey = keyfile.read()


privkey = None
with open('keypair.pem', 'r') as keyfile:
    privkey = keyfile.read()

# assemble claims
# we're building 3 example payloads
good_payload = {
   'exp': datetime.now(tz=timezone.utc) + timedelta(hours=1),
   'alg': 'RS256',
   'iss': 'me',
   'iat': datetime.now(tz=timezone.utc),
   'nbf': datetime.now(tz=timezone.utc),
   'aud': ['me', 'you'],
}

expired_payload = {
   'exp': datetime.now(tz=timezone.utc),
   'alg': 'RS256',
   'iss': 'me',
   'iat': datetime.now(tz=timezone.utc),
   'nbf': datetime.now(tz=timezone.utc),
   'aud': ['me', 'you'],
}

bad_audience_payload = {
   'exp': datetime.now(tz=timezone.utc) + timedelta(hours=1),
   'alg': 'RS256',
   'iss': 'me',
   'iat': datetime.now(tz=timezone.utc),
   'nbf': datetime.now(tz=timezone.utc),
   'aud': ['me', 'not you'],
}


# build tokens with pyjwt
def process_token(payload):
    token = jwt.encode(
                 payload,
                 privkey,
                 algorithm='RS256',
#                 headers={'kid': 'this one'},  <- here's where we add a kid to the header
    )
    print(f'This is the encoded token: {token}\n\n')
    headers = jwt.get_unverified_header(token)
    print(f'This is the token headers {headers}\n\n')
    decoded = jwt.decode(token, pubkey, audience='you', algorithms=['RS256'])
    print(f'This is the decoded token {decoded}\n\n')


#print(process_token(good_payload))
#print(process_token(expired_payload))
#print(process_token(bad_audience_payload))

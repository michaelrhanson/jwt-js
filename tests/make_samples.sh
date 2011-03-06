cat jwtClaim.txt | openssl base64 -e  > jwtClaim.b64
tr -d '\012'  < jwtClaim.b64 > jwtClaim.b64oneline
openssl dgst -sha1 -binary < jwtClaim.b64oneline | openssl base64 -e > jwtClaimDigest.sha1
openssl dgst -sha256 -binary < jwtClaim.b64oneline | openssl base64 -e > jwtClaimDigest.sha256
openssl dgst -sha256 -binary -sign key.pem  < jwtClaim.b64oneline | openssl base64 -e > rsa_sha256_signature

openssl dgst -sha256 -binary -hmac `echo -n "hmackey"`  < jwtClaim.b64oneline | openssl base64 -e > hmac_sha256_signature

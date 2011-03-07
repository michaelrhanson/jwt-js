echo -n "." > delimiter
cat rs256header.b64 delimiter jwtClaim.b64 > rs256SigningInput
cat hs256header.b64 delimiter jwtClaim.b64 > hs256SigningInput

openssl dgst -sha256 -binary < rs256SigningInput | openssl base64 -e > jwtClaimDigest.sha256
openssl dgst -sha256 -binary -sign key.pem  < rs256SigningInput | openssl base64 -e > rsa_sha256_signature

openssl dgst -sha256 -binary -hmac `echo -n "hmackey"`  < hs256SigningInput | openssl base64 -e > hmac_sha256_signature

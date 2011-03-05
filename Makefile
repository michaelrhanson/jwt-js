

SJCL_LIBS = lib/sjcl/sjcl.js
TWU_RSA_LIBS = lib/twu-rsa/base64.js lib/twu-rsa/jsbn.js lib/twu-rsa/jsbn2.js lib/twu-rsa/rsa.js lib/twu-rsa/rsa2.js
KURUSHIMA_JSRSA_LIBS = lib/kurushima-jsrsa/asn1hex.js lib/kurushima-jsrsa/rsa-pem.js lib/kurushima-jsrsa/rsa-sign.js lib/kurushima-jsrsa/x509.js

LIBS = $(SJCL_LIBS) $(TWU_RSA_LIBS) $(KURUSHIMA_JSRSA_LIBS)

dist:
	mkdir -p build
	cat $(LIBS) src/jwt-token.js > build/jwt.js
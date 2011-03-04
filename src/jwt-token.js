function HMACAlgorithm(hash, key)
{
  this.hash = hash;
  this.key = key;
}

HMACAlgorithm.prototype = 
{
  update: function _update(data)
  {
    this.data = data;
  },
  
  finalize: function _finalize()
  {
  },
  
  sign: function _sign()
  {
    return window.btoa(Crypto.HMAC(this.hash, this.data, this.key, {asString:true}));
  }
}

function RSASHAAlgorithm(hash, keyPEM)
{
  if (hash == "sha1") {
    this.hash = "sha1";
  } else if (hash == "sha256") {
    this.hash = "sha256";
  } else {
    throw NoSuchAlgorithmException("JWT algorithm: " + jwtAlgStr);  
  }
  this.keyPEM = keyPEM;
}
RSASHAAlgorithm.prototype =
{
  update: function _update(data)
  {
    this.data = data;
  },
  finalize: function _finalize()
  {
  
  },
  sign: function _sign()
  {
    var rsa = new RSAKey();
    rsa.readPrivateKeyFromPEMString(this.keyPEM);
    var hSig = rsa.signString(this.data, this.hash);
    return hex2b64(hSig);
  }
}

function WebToken(objectStr, algorithm)
{
  this.jsonStr = objectStr;
  this.pkAlgorithm = algorithm;
}

function jsonObj(strOrObject)
{
  if (typeof strOrObject == "string") {
    return JSON.parse(strOrObject);
  }
  return strOrObject;
}

WebToken.prototype =
{
  serialize: function _serialize(key)
  {
    var header = jsonObj(this.pkAlgorithm);
    var jwtAlgStr = header.alg;
    var algorithm;
    
    if ("ES256" === jwtAlgStr) {
      //oid = SECObjectIdentifiers.secp256r1;
      algorithm = new SHA256Digest();
    } else if ("ES384" === jwtAlgStr) {
      //oid = SECObjectIdentifiers.secp384r1;
      algorithm = new SHA384Digest();
    } else if ("ES512" === jwtAlgStr) {
      //oid = SECObjectIdentifiers.secp521r1;
      algorithm = new SHA512Digest();
    } else if ("HS256" === jwtAlgStr) {
      algorithm = new HMACAlgorithm(Crypto.SHA256, key);
    } else if ("RS256" === jwtAlgStr) {
      algorithm = new RSASHAAlgorithm("sha256", key);
    } else {
      throw NoSuchAlgorithmException("JWT algorithm: " + jwtAlgStr);
    }

    var algBytes = window.btoa(this.pkAlgorithm);
    var jsonBytes = window.btoa(this.jsonStr);
    var stringToSign = algBytes + "." + jsonBytes;
    algorithm.update(stringToSign); // or something?
    var digestValue = algorithm.finalize();
    var signatureValue = algorithm.sign();

    dump(signatureValue+"\n");
    return stringToSign + "." + signatureValue;
  },
  
  verify: function _verify()
  {
  }
}


function NoSuchAlgorithmException(message) {
  this.toString = function() { return "No such algorithm: "+this.message; };
}
function NotImplementedException(message) {
  this.toString = function() { return "Not implemented: "+this.message; };
}

function HMACAlgorithm(hash, key)
{
  if (hash == "sha256") {
    this.hash = sjcl.hash.sha256;
  } else {
    throw new NoSuchAlgorithmException("HMAC does not support hash " + hash);
  }
  this.key = sjcl.codec.utf8String.toBits(key);
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
    var hmac = new sjcl.misc.hmac(this.key, this.hash);
    var result = hmac.encrypt(this.data);
    return sjcl.codec.base64.fromBits(result);
  }
}

function RSASHAAlgorithm(hash, keyPEM)
{
  if (hash == "sha1") {
    this.hash = "sha1";
  } else if (hash == "sha256") {
    this.hash = "sha256";
  } else {
    throw new NoSuchAlgorithmException("JWT algorithm: " + hash);  
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
  this.objectStr = objectStr;
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
      throw new NotImplementedException("JWT algorithm: " + jwtAlgStr);
    } else if ("ES384" === jwtAlgStr) {
      throw new NotImplementedException("JWT algorithm: " + jwtAlgStr);
    } else if ("ES512" === jwtAlgStr) {
      throw new NotImplementedException("JWT algorithm: " + jwtAlgStr);
    } else if ("HS256" === jwtAlgStr) {
      algorithm = new HMACAlgorithm("sha256", key);
    } else if ("RS256" === jwtAlgStr) {
      algorithm = new RSASHAAlgorithm("sha256", key);
    } else {
      throw new NoSuchAlgorithmException("JWT algorithm: " + jwtAlgStr);
    }

    var algBytes = window.btoa(this.pkAlgorithm);
    var jsonBytes = window.btoa(this.objectStr);
    algorithm.update(jsonBytes);
    var digestValue = algorithm.finalize();
    var signatureValue = algorithm.sign();
    return algBytes + "." + jsonBytes + "." + signatureValue;
  },
  
  verify: function _verify()
  {
    var header = jsonObj(this.pkAlgorithm);
    var jwtAlgStr = header.alg;
    var algorithm;
    
    if ("ES256" === jwtAlgStr) {
      throw NotImplementedException("JWT algorithm: " + jwtAlgStr);
    } else if ("ES384" === jwtAlgStr) {
      throw NotImplementedException("JWT algorithm: " + jwtAlgStr);
    } else if ("ES512" === jwtAlgStr) {
      throw NotImplementedException("JWT algorithm: " + jwtAlgStr);
    } else if ("HS256" === jwtAlgStr) {
      algorithm = new HMACAlgorithm(Crypto.SHA256, key);
    } else if ("RS256" === jwtAlgStr) {
      algorithm = new RSASHAAlgorithm("sha256", key);
    } else {
      throw NoSuchAlgorithmException("JWT algorithm: " + jwtAlgStr);
    }

    var algBytes = window.btoa(this.pkAlgorithm);
    var jsonBytes = window.btoa(this.objectStr);
    algorithm.update(jsonBytes);
    var digestValue = algorithm.finalize();
    var signatureValue = algorithm.sign();

    return algBytes + "." + jsonBytes + "." + signatureValue;


  }
}


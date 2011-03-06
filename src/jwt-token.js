var jwt = {};

var JWTInternals = (function() {

  function base64urlencode(arg)
  {
    var s = window.btoa(arg); // Standard base64 encoder
    s = s.split('=')[0]; // Remove any trailing '='s
    s = s.replace('+', '-', 'g'); // 62nd char of encoding
    s = s.replace('/', '_', 'g'); // 63rd char of encoding
    // TODO optimize this; we can do much better
    return s;
  }

  function base64urldecode(arg)
  {
    var s = arg;
    s = s.replace('-', '+', 'g'); // 62nd char of encoding
    s = s.replace('_', '/', 'g'); // 63rd char of encoding
    switch (s.length % 4) // Pad with trailing '='s
    {
      case 0: break; // No pad chars in this case
      case 2: s += "=="; break; // Two pad chars
      case 3: s += "="; break; // One pad char
      default: throw new InputException("Illegal base64url string!");
    }
    return window.atob(s); // Standard base64 decoder
  }

  function NoSuchAlgorithmException(message) {
    this.message = message;
    this.toString = function() { return "No such algorithm: "+this.message; };
  }
  function NotImplementedException(message) {
    this.message = message;
    this.toString = function() { return "Not implemented: "+this.message; };
  }
  function InputException(message) {
    this.message = message;
    this.toString = function() { return "Malformed input: "+this.message; };
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
    },
    
    verify: function _verify(sig)
    {
      var hmac = new sjcl.misc.hmac(this.key, this.hash);
      var result = hmac.encrypt(this.data);
      return sjcl.codec.base64.fromBits(result) == sig; 
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
    },
    verify: function _verify(sig)
    {
      var result = this.keyPEM.verifyString(this.data, b64tohex(sig));
      return result;
    }
  }

  function WebToken(objectStr, algorithm)
  {
    this.objectStr = objectStr;
    this.pkAlgorithm = algorithm;
  }

  var WebTokenParser = {

    parse: function _parse(input)
    {
      var parts = input.split(".");
      if (parts.length != 3) {
        throw new MalformedWebToken("Must have three parts");
      }
      var token = new WebToken();
      token.pkAlgorithm = window.atob(parts[0]);
      token.jsonObjectStr = parts[1];
      token.claimedSignature = parts[2];
      return token;
    }
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
    
    verify: function _verify(key)
    {
      var header = jsonObj(this.pkAlgorithm);
      var jwtAlgStr = header.alg;
      var algorithm;
      
      if ("ES256" === jwtAlgStr) {
        throw new NotImplementedException("ECDSA256 not yet implemented");
      } else if ("ES384" === jwtAlgStr) {
        throw new NotImplementedException("ECDSA384 not yet implemented");
      } else if ("ES512" === jwtAlgStr) {
        throw new NotImplementedException("ECDSA512 not yet implemented");
      } else if ("HS256" === jwtAlgStr) {
        algorithm = new HMACAlgorithm("sha256", key);
      } else if ("RS256" === jwtAlgStr) {
        algorithm = new RSASHAAlgorithm("sha256", key);
      } else {
        throw new NoSuchAlgorithmException("JWT algorithm: " + jwtAlgStr);
      }

      algorithm.update(this.jsonObjectStr);
      algorithm.finalize();
      return algorithm.verify(this.claimedSignature);
    }
  }
  
  jwt.WebToken = WebToken;
  jwt.WebTokenParser = WebTokenParser;
  jwt.base64urlencode = base64urlencode;
  jwt.base64urldecode = base64urldecode;
})();
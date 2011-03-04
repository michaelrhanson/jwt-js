/*  /_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/
	charset= shift_jis
	
    SHA-256
    FIPS 180-2
    http://csrc.nist.gov/cryptval/shs.html

    LastModified : 2006-11/14
    
    Written by kerry
    http://user1.matsumoto.ne.jp/~goma/

    “®ìƒuƒ‰ƒEƒU :: IE4+ , NN4.06+ , Gecko , Opera6
    
    ----------------------------------------------------------------
    
    Usage
    
    // •Ô‚è’l‚ð 16i”‚Å“¾‚é
    sha256hash = sha256.hex( data );
	
	// •Ô‚è’l‚ðƒoƒCƒiƒŠ‚Å“¾‚é
    sha256bin = sha256.bin( data );
    
    // •Ô‚è’l‚ð10i”‚Ì”z—ñ‚Å“¾‚é
    sha256decs = sha256.dec( data );
    
    
	* data		-> ƒnƒbƒVƒ…’l‚ð“¾‚½‚¢ƒf[ƒ^
				data ‚ÍƒAƒ“ƒpƒbƒNÏ‚Ý‚Ì”z—ñ‚Å‚à‰Â”\

	// e.g.
	
	var data_1 = "abc";
	var hash_1 = sha256.hex( data_1 );
	var data_2 = sha256 Array(data_1.charCodeAt(0), data_1.charCodeAt(1), data_1.charCodeAt(2));
	var hash_2 = sha256.hex( data_2 );
	
	alert( hash_1 === hash_2 ); // true
	
/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/   */


sha256 = new function()
{
	var blockLen = 64;
	var state = [ 	0x6a09e667 , 0xbb67ae85 , 0x3c6ef372 , 0xa54ff53a ,
        			0x510e527f , 0x9b05688c , 0x1f83d9ab , 0x5be0cd19 ];
	var sttLen = state.length;
	
	this.hex = function(_data)
	{
		return toHex( getMD(_data) );
	}

	this.dec = function(_data)
	{
		return getMD(_data);
	}
	
	this.bin = function(_data)
	{
		return pack( getMD(_data) );
	}
	
	var getMD = function(_data)
	{
		var datz = [];
		if (isAry(_data)) datz = _data;
		else if (isStr(_data)) datz = unpack(_data);
		else "unknown type";
		datz = paddingData(datz);
		return round(datz);
	}
    
    var isAry = function(_ary)
	{
		return _ary && _ary.constructor === [].constructor;
	}
	var isStr = function(_str)
	{
		return typeof(_str) == typeof("string");
	}

    var rotr = function(_v, _s) { return (_v >>> _s) | (_v << (32 - _s)) };

    var S0 = function(_v) { return rotr(_v,  2) ^ rotr(_v, 13) ^ rotr(_v, 22) };
    var S1 = function(_v) { return rotr(_v,  6) ^ rotr(_v, 11) ^ rotr(_v, 25) };
    var s0 = function(_v) { return rotr(_v,  7) ^ rotr(_v, 18) ^ (_v >>>  3) };
    var s1 = function(_v) { return rotr(_v, 17) ^ rotr(_v, 19) ^ (_v >>> 10) };

    var ch = function(_b, _c, _d) { return (_b & _c) ^ (~_b & _d) };
    var maj = function(_b, _c, _d) { return (_b & _c) ^ (_b & _d) ^ (_c & _d) };
    
	var round = function(_blk)
	{
		var stt = [];
		var tmpS= [];
		var i, j, tmp1, tmp2, x = [];
		for (j=0; j<sttLen; j++) stt[j] = state[j];
		
		for (i=0; i<_blk.length; i+=blockLen)
		{
			for (j=0; j<sttLen; j++) tmpS[j] = stt[j];
			x = toBigEndian32( _blk.slice(i, i+ blockLen) );
			for (j=16; j<64; j++)
            	x[j] = s1(x[ j-2 ]) + x[ j-7 ] + s0(x[ j-15 ]) + x[ j-16 ];
		
	        for (j=0; j<64; j++)
	        {
	            tmp1 = stt[7] + S1(stt[4]) + ch( stt[4], stt[5], stt[6] ) + K[j] + x[j];
	            tmp2 = S0(stt[0]) + maj( stt[0], stt[1], stt[2] );
	            
	            stt[7] = stt[6];
	            stt[6] = stt[5];
	            stt[5] = stt[4];
	            stt[4] = stt[3] + tmp1;
	            stt[3] = stt[2];
	            stt[2] = stt[1];
	            stt[1] = stt[0];
	            stt[0] = tmp1 + tmp2;
	        }
			for (j=0; j<sttLen; j++) stt[j] += tmpS[j];
		}

		return fromBigEndian32(stt);
	}

	var paddingData = function(_datz)
	{
		var datLen = _datz.length;
		var n = datLen;
		_datz[n++] = 0x80;
		while (n% blockLen != 56) _datz[n++] = 0;
		datLen *= 8;
		return _datz.concat(0, 0, 0, 0, fromBigEndian32([datLen]) );
	}

	var toHex = function(_decz)
	{
		var i, hex = "";

		for (i=0; i<_decz.length; i++)
			hex += (_decz[i]>0xf?"":"0")+ _decz[i].toString(16);
		return hex;
	}
	
	var fromBigEndian32 = function(_blk)
	{
		var tmp = [];
		for (n=i=0; i<_blk.length; i++)
		{
			tmp[n++] = (_blk[i] >>> 24) & 0xff;
			tmp[n++] = (_blk[i] >>> 16) & 0xff;
			tmp[n++] = (_blk[i] >>>  8) & 0xff;
			tmp[n++] = _blk[i] & 0xff;
		}
		return tmp;
	}
	
	var toBigEndian32 = function(_blk)
	{
		var tmp = [];
		var i, n;
		for (n=i=0; i<_blk.length; i+=4, n++)
			tmp[n] = (_blk[i]<<24) | (_blk[i+ 1]<<16) | (_blk[i+ 2]<<8) | _blk[i+ 3];
		return tmp;
	}
	
	var unpack = function(_dat)
	{
		var i, n, c, tmp = [];

	    for (n=i=0; i<_dat.length; i++) 
	    {
	    	c = _dat.charCodeAt(i);
			if (c <= 0xff) tmp[n++] = c;
			else {
				tmp[n++] = c >>> 8;
				tmp[n++] = c &  0xff;
			}	
	    }
	    return tmp;
	}

	var pack = function(_ary)
    {
        var i, tmp = "";
        for (i in _ary) tmp += String.fromCharCode(_ary[i]);
        return tmp;
    }


    var K = [
        0x428a2f98 , 0x71374491 , 0xb5c0fbcf , 0xe9b5dba5 , 
        0x3956c25b , 0x59f111f1 , 0x923f82a4 , 0xab1c5ed5 , 
        0xd807aa98 , 0x12835b01 , 0x243185be , 0x550c7dc3 , 
        0x72be5d74 , 0x80deb1fe , 0x9bdc06a7 , 0xc19bf174 , 

        0xe49b69c1 , 0xefbe4786 , 0x0fc19dc6 , 0x240ca1cc , 
        0x2de92c6f , 0x4a7484aa , 0x5cb0a9dc , 0x76f988da , 
        0x983e5152 , 0xa831c66d , 0xb00327c8 , 0xbf597fc7 , 
        0xc6e00bf3 , 0xd5a79147 , 0x06ca6351 , 0x14292967 , 

        0x27b70a85 , 0x2e1b2138 , 0x4d2c6dfc , 0x53380d13 , 
        0x650a7354 , 0x766a0abb , 0x81c2c92e , 0x92722c85 , 
        0xa2bfe8a1 , 0xa81a664b , 0xc24b8b70 , 0xc76c51a3 , 
        0xd192e819 , 0xd6990624 , 0xf40e3585 , 0x106aa070 , 

        0x19a4c116 , 0x1e376c08 , 0x2748774c , 0x34b0bcb5 , 
        0x391c0cb3 , 0x4ed8aa4a , 0x5b9cca4f , 0x682e6ff3 , 
        0x748f82ee , 0x78a5636f , 0x84c87814 , 0x8cc70208 , 
        0x90befffa , 0xa4506ceb , 0xbef9a3f7 , 0xc67178f2 
    ];
}



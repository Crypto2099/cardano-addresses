/*
  Pointers in emscripten compiled code are represented as offsets
  into the global HEAP ArrayBuffer.

  GHCJS pointers (Addr#) and unlifted arrays (ByteArray# etc.) are represented
  as a pair of a buffer and an offset.
 */

function h$logWrapper(x) {
  /* console.log(x); */
}

function h$copyToHeap(buf_d, buf_o, tgt, len) {
  if(len === 0) return;
  var u8 = buf_d.u8;
  var hexes = "";
  for(var i=0;i<len;i++) {
    h$cardano_crypto.HEAPU8[tgt+i] = u8[buf_o+i];
    hexes += h$toHex(u8[buf_o+i]);
  }
  // h$logWrapper("=> " + len + " " + hexes + " " + buf_o + " " + buf_d.len);
}

function h$copyFromHeap(src, buf_d, buf_o, len) {
  var u8 = buf_d.u8;
  var hexes = "";
  for(var i=0;i<len;i++) {
    u8[buf_o+i] = h$cardano_crypto.HEAPU8[src+i];
    hexes += h$toHex(h$cardano_crypto.HEAPU8[src+i]);
  }
  // h$logWrapper("<= " + len + " " + hexes + " " + buf_o + " " + buf_d.len);
}

function h$toHex(n) {
  var s = n.toString(16);
  if(s.length === 1) s = '0' + s;
  return s;
}

var h$buffers     = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0];
var h$bufferSizes = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0];

function h$getTmpBuffer(n, minSize) {
  var sn = h$bufferSizes[n];
  if(sn < minSize) {
    if(sn > 0) {
      h$cardano_crypto._free(h$buffers[n]);
    }
    h$buffers[n] = h$cardano_crypto._malloc(2*minSize); // fixme 2* shouldn't be needed
    h$bufferSizes[n] = minSize;
  }
  return h$buffers[n];
}

function h$getTmpBufferWith(n, buf_d, buf_o, len) {
  // fixme: we can avoid the copying if the buffer is already the actual
  //        heap buffer
  var buf_ptr = h$getTmpBuffer(n, len);
  h$copyToHeap(buf_d, buf_o, buf_ptr, len);
  return buf_ptr;
}

/* ED25519 */
var h$ed25519_pk_size      = 32;
var h$ed25519_sk_size      = 64;
var h$ed25519_sig_size     = 64;

function h$cardano_crypto_ed25519_sign_open(m_d, m_o, mlen, pk_d, pk_o, sig_d, sig_o) {
  h$logWrapper("h$cardano_crypto_ed25519_sign_open");
  var m_ptr   = h$getTmpBufferWith(0, m_d,   m_o,   mlen),
      pk_ptr  = h$getTmpBufferWith(1, pk_d,  pk_o,  h$ed25519_pk_size),
      sig_ptr = h$getTmpBufferWith(2, sig_d, sig_o, h$ed25519_sig_size);
  return h$cardano_crypto._cardano_crypto_ed25519_sign_open(m_ptr, mlen, pk_ptr, sig_ptr);
}

function h$cardano_crypto_ed25519_sign(m_d, m_o, mlen, salt_d, salt_o, slen, sk_d, sk_o, pk_d, pk_o, sig_d, sig_o) {
  h$logWrapper("h$cardano_crypto_ed25519_sign");
  var m_ptr    = h$getTmpBufferWith(0, m_d, m_o, mlen),
      salt_ptr = h$getTmpBufferWith(1, salt_d, salt_o, slen),
      sk_ptr   = h$getTmpBufferWith(2, sk_d, sk_o, h$ed25519_sk_size),
      pk_ptr   = h$getTmpBufferWith(3, pk_d, pk_o, h$ed25519_pk_size),
      sig_ptr  = h$getTmpBuffer(4, h$ed25519_sig_size);
  h$cardano_crypto._cardano_crypto_ed25519_sign
             (m_ptr, mlen, salt_ptr, slen, sk_ptr, pk_ptr, sig_ptr);
  h$copyFromHeap(sig_ptr, sig_d, sig_o, h$ed25519_sig_size);
}

function h$cardano_crypto_ed25519_publickey(sk_d, sk_o, pk_d, pk_o) {
  h$logWrapper("h$cardano_crypto_ed25519_publickey");
  var sk_ptr = h$getTmpBufferWith(0, sk_d, sk_o, h$ed25519_sk_size),
      pk_ptr = h$getTmpBuffer(1, h$ed25519_pk_size);
  h$cardano_crypto._cardano_crypto_ed25519_publickey(sk_ptr, pk_ptr);
  h$copyFromHeap(pk_ptr, pk_d, pk_o, h$ed25519_pk_size);
}

function h$cardano_crypto_ed25519_point_add(pk1_d, pk1_o, pk2_d, pk2_o, res_d, res_o) {
  h$logWrapper("h$cardano_crypto_ed25519_point_add");
  var pk1_ptr = h$getTmpBufferWith(0, pk1_d, pk1_o, h$ed25519_pk_size),
      pk2_ptr = h$getTmpBufferWith(1, pk2_d, pk2_o, h$ed25519_pk_size),
      res_ptr = h$getTmpBuffer(2, h$ed25519_pk_size);
  var r = h$cardano_crypto._cardano_crypto_ed25519_point_add(pk1_ptr, pk2_ptr, res_ptr);
  h$copyFromHeap(res_ptr, res_d, res_o, h$ed25519_pk_size);
  return r;
}

// temporary fixes

// XXX fix this in thrunner.js probably
if(typeof __dirname == 'undefined') {
  var __dirname = '/';
}

function h$getMonotonicNSec() {
  var t = BigInt((new Date()).getTime())*1000n;
  h$ret1 = Number(t&0xffffffffn);
  return Number((t>>32n)&0xffffffffn);
}

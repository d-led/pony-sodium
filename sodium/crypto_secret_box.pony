
use "lib:sodium"

use @crypto_secretbox_macbytes[USize]()
use @crypto_secretbox_keybytes[USize]()
use @crypto_secretbox_noncebytes[USize]()
use @crypto_secretbox_easy[_Int](
      buf: Pointer[None] iso, m: Pointer[None] iso, m_size: USize, n: Pointer[None] iso, k: Pointer[None] iso
    )
use @crypto_secretbox_open_easy[_Int](
      buf: Pointer[None] iso, c: Pointer[None] iso, c_size: USize, n: Pointer[None] iso, k: Pointer[None] iso
    )

class val CryptoSecretBoxKey
  let _inner: String
  fun string(): String => _inner
  fun cpointer(): Pointer[U8] tag => _inner.cpointer()
  fun is_valid(): Bool => _inner.size() == CryptoSecretBox.key_size()
  new val create(buf: (ReadSeq[U8] iso | ReadSeq[U8] val)) =>
    _inner = recover String.>append(consume buf) end

class val CryptoSecretBoxNonce
  let _inner: String
  fun string(): String => _inner
  fun cpointer(): Pointer[U8] tag => _inner.cpointer()
  fun is_valid(): Bool => _inner.size() == CryptoSecretBox.nonce_size()
  new val create(buf: (ReadSeq[U8] iso | ReadSeq[U8] val)) =>
    _inner = recover String.>append(consume buf) end

primitive CryptoSecretBox
  fun tag mac_size(): USize   => @crypto_secretbox_macbytes().usize()
  fun tag key_size(): USize   => @crypto_secretbox_keybytes().usize()
  fun tag nonce_size(): USize => @crypto_secretbox_noncebytes().usize()
  
  fun tag _make_buffer(size: USize): String iso^ =>
    recover String.from_cpointer(
      @pony_alloc(@pony_ctx(), size), size
    ) end
  
  fun tag random_bytes(size: USize): String iso^ =>
    let buf = _make_buffer(size)
    @randombytes_buf(buf.cpointer(), size)
    buf
  
  fun tag key(): CryptoSecretBoxKey =>
    CryptoSecretBoxKey(random_bytes(key_size()))
  
  fun tag nonce(): CryptoSecretBoxNonce =>
    CryptoSecretBoxNonce(random_bytes(nonce_size()))
  
  fun tag apply(m: String, n: CryptoSecretBoxNonce, k: CryptoSecretBoxKey): String? =>
    if not (n.is_valid() and k.is_valid()) then error end
    let buf_size = m.size() + mac_size()
    let buf = _make_buffer(buf_size)
    if 0 != @crypto_secretbox_easy(
      buf.cpointer(), m.cpointer(), m.size(), n.cpointer(), k.cpointer()
    ) then error end
    consume buf
  
  fun tag open(c: String, n: CryptoSecretBoxNonce, k: CryptoSecretBoxKey): String? =>
    if not (n.is_valid() and k.is_valid()) then error end
    let buf_size = c.size() - mac_size()
    let buf = _make_buffer(buf_size)
    if 0 != @crypto_secretbox_open_easy(
      buf.cpointer(), c.cpointer(), c.size(), n.cpointer(), k.cpointer()
    ) then error end
    consume buf
  
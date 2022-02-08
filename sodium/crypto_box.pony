
use "lib:sodium"

use @crypto_box_seedbytes[USize]()
use @crypto_box_secretkeybytes[USize]()
use @crypto_box_publickeybytes[USize]()
use @crypto_box_noncebytes[USize]()
use @crypto_box_macbytes[USize]()
use @crypto_scalarmult_bytes[USize]()
use @crypto_box_keypair[_Int](pk: Pointer[None] iso, sk: Pointer[None] iso)
use @crypto_box_seed_keypair[_Int](
      pk: Pointer[None] iso, sk: Pointer[None] iso, seed: Pointer[None] iso
    )
use @crypto_box_easy[_Int](
      buf: Pointer[None] iso, m: Pointer[None] iso, m_size: USize, n: Pointer[None] iso, pk: Pointer[None] iso, sk: Pointer[None] iso
    )
use @crypto_box_open_easy[_Int](
      buf: Pointer[None] iso, c: Pointer[None] iso, c_size: USize, n: Pointer[None] iso, pk: Pointer[None] iso, sk: Pointer[None] iso
    )
use @crypto_scalarmult_base[_Int](
      buf: Pointer[None] iso, sk: Pointer[None] iso
    )
use @crypto_scalarmult[_Int](
      buf: Pointer[None] iso, sk: Pointer[None] iso, pk: Pointer[None] iso
    )

class val CryptoBoxSeed
  let _inner: String
  fun string(): String => _inner
  fun cpointer(): Pointer[U8] tag => _inner.cpointer()
  fun is_valid(): Bool => _inner.size() == CryptoBox.seed_size()
  new val create(buf: (ReadSeq[U8] iso | ReadSeq[U8] val)) =>
    _inner = recover String.>append(consume buf) end

class val CryptoBoxSecretKey
  let _inner: String
  fun string(): String => _inner
  fun cpointer(): Pointer[U8] tag => _inner.cpointer()
  fun is_valid(): Bool => _inner.size() == CryptoBox.secret_key_size()
  new val create(buf: (ReadSeq[U8] iso | ReadSeq[U8] val)) =>
    _inner = recover String.>append(consume buf) end

class val CryptoBoxPublicKey
  let _inner: String
  fun string(): String => _inner
  fun cpointer(): Pointer[U8] tag => _inner.cpointer()
  fun is_valid(): Bool => _inner.size() == CryptoBox.public_key_size()
  new val create(buf: (ReadSeq[U8] iso | ReadSeq[U8] val)) =>
    _inner = recover String.>append(consume buf) end

class val CryptoBoxNonce
  let _inner: String
  fun string(): String => _inner
  fun cpointer(): Pointer[U8] tag => _inner.cpointer()
  fun is_valid(): Bool => _inner.size() == CryptoBox.nonce_size()
  new val create(buf: (ReadSeq[U8] iso | ReadSeq[U8] val)) =>
    _inner = recover String.>append(consume buf) end

primitive CryptoBox
  fun tag seed_size(): USize       => @crypto_box_seedbytes().usize()
  fun tag secret_key_size(): USize => @crypto_box_secretkeybytes().usize()
  fun tag public_key_size(): USize => @crypto_box_publickeybytes().usize()
  fun tag nonce_size(): USize      => @crypto_box_noncebytes().usize()
  fun tag mac_size(): USize        => @crypto_box_macbytes().usize()
  fun tag scalar_size(): USize     => @crypto_scalarmult_bytes().usize()
  
  fun tag _make_buffer(size: USize): String iso^ =>
    recover String.from_cpointer(
      @pony_alloc(@pony_ctx(), size), size
    ) end
  
  fun tag random_bytes(size: USize): String iso^ =>
    let buf = _make_buffer(size)
    @randombytes_buf(buf.cpointer(), size)
    buf
  
  fun tag nonce(): CryptoBoxNonce =>
    CryptoBoxNonce(random_bytes(nonce_size()))
  
  fun tag keypair(): (CryptoBoxSecretKey, CryptoBoxPublicKey)? =>
    let sk_size = secret_key_size(); let sk = _make_buffer(sk_size)
    let pk_size = public_key_size(); let pk = _make_buffer(pk_size)
    if 0 != @crypto_box_keypair(pk.cpointer(), sk.cpointer()) then error end
    (CryptoBoxSecretKey(consume sk), CryptoBoxPublicKey(consume pk))
  
  fun tag seed_keypair(seed: CryptoBoxSeed): (CryptoBoxSecretKey, CryptoBoxPublicKey)? =>
    if not seed.is_valid() then error end
    let sk_size = secret_key_size(); let sk = _make_buffer(sk_size)
    let pk_size = public_key_size(); let pk = _make_buffer(pk_size)
    if 0 != @crypto_box_seed_keypair(
      pk.cpointer(), sk.cpointer(), seed.cpointer()
    ) then error end
    (CryptoBoxSecretKey(consume sk), CryptoBoxPublicKey(consume pk))
  
  fun tag apply(m: String, n: CryptoBoxNonce, sk: CryptoBoxSecretKey, pk: CryptoBoxPublicKey): String? =>
    if not (n.is_valid() and pk.is_valid() and sk.is_valid()) then error end
    let buf_size = m.size() + mac_size()
    let buf = _make_buffer(buf_size)
    if 0 != @crypto_box_easy(
      buf.cpointer(), m.cpointer(), m.size(), n.cpointer(), pk.cpointer(), sk.cpointer()
    ) then error end
    consume buf
  
  fun tag open(c: String, n: CryptoBoxNonce, sk: CryptoBoxSecretKey, pk: CryptoBoxPublicKey): String? =>
    if not (n.is_valid() and pk.is_valid() and sk.is_valid()) then error end
    let buf_size = c.size() - mac_size()
    let buf = _make_buffer(buf_size)
    if 0 != @crypto_box_open_easy(
      buf.cpointer(), c.cpointer(), c.size(), n.cpointer(), pk.cpointer(), sk.cpointer()
    ) then error end
    consume buf
  
  fun tag scalar_mult_base(sk: CryptoBoxSecretKey): CryptoBoxPublicKey? =>
    if not sk.is_valid() then error end
    let buf = _make_buffer(public_key_size())
    if 0 != @crypto_scalarmult_base(
      buf.cpointer(), sk.cpointer()
    ) then error end
    CryptoBoxPublicKey(consume buf)
  
  fun tag scalar_mult(sk: CryptoBoxSecretKey, pk: CryptoBoxPublicKey): String? =>
    if not (pk.is_valid() and sk.is_valid()) then error end
    let buf = _make_buffer(scalar_size())
    if 0 != @crypto_scalarmult(
      buf.cpointer(), sk.cpointer(), pk.cpointer()
    ) then error end
    consume buf

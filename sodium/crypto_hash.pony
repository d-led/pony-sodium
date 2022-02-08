
use "lib:sodium"

use @crypto_hash_sha256_bytes[USize]()
use @crypto_hash_sha512_bytes[USize]()
use @crypto_hash_sha256[_Int](
      buf: Pointer[None] iso, m: Pointer[None] iso, m_size: USize
    )
use @crypto_hash_sha512[_Int](
      buf: Pointer[None] iso, m: Pointer[None] iso, m_size: USize
    )

primitive CryptoHash
  fun tag sha256_size(): USize => @crypto_hash_sha256_bytes().usize()
  fun tag sha512_size(): USize => @crypto_hash_sha512_bytes().usize()
  
  fun tag _make_buffer(size: USize): String iso^ =>
    recover String.from_cpointer(
      @pony_alloc(@pony_ctx(), size), size
    ) end
  
  fun tag sha256(m: String): String =>
    let buf = _make_buffer(sha256_size())
    @crypto_hash_sha256(
      buf.cpointer(), m.cpointer(), m.size()
    )
    consume buf
  
  fun tag sha512(m: String): String =>
    let buf = _make_buffer(sha512_size())
    @crypto_hash_sha512(
      buf.cpointer(), m.cpointer(), m.size()
    )
    consume buf


use "lib:sodium"

use @sodium_init[None]()

primitive _Lib
  fun _init() =>
    @sodium_init()

type _UChar is U8
type _Int   is I32

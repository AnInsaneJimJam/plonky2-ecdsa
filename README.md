# ECDSA gadgets for Plonky2

## Vendored copy

This copy is pinned from
[`dadantas/plonky2-ecdsa@d1935c4`](https://github.com/dadantas/plonky2-ecdsa/commit/d1935c48392e2f7587a918e0a32ccbde151581b5),
which ports the original Polygon Zero crate to Plonky2 1.1. It is kept local so
the benchmark can use the same pinned `plonky2_u32` source as its other
circuits.

Local changes are limited to the dependency pin, complete serialization for
the custom witness generators, and current-toolchain lint fixes. The upstream
generator serialization methods were placeholders, so this copy also exports
the serializer needed to measure and round-trip circuit preprocessing data.

## License

Licensed under either of

* Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
* MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.


### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.

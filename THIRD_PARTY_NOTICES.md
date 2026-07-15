# Third-Party Notices

## AVX2 16-bit Montgomery forward and inverse NTTs

The repository-local AVX2 forward and inverse NTTs in `baby-mlkem.c` use C
intrinsics implementations of Montgomery butterfly arithmetic and the
precomputed low/high twiddle-factor decomposition used by the Kyber reference
and AVX2 implementations retained in this repository (upstream project:
https://github.com/pq-crystals/kyber):

- `include/kyber_upstream/ref/ntt.c`
- `include/kyber_upstream/ref/reduce.c`
- `include/kyber_upstream/avx2/ntt.S`
- `include/kyber_upstream/avx2/fq.inc`

The baby-mlkem paths do not link or call those vendored NTT objects. The local
intrinsics implementations and their seven-stage range boundaries are
maintained separately, but the underlying arithmetic design is externally
derived and is not claimed as an independently invented baby-mlkem NTT method.
The retained Kyber/PQClean sources are public-domain/CC0 code; see
`include/pqclean_avx2/ml-kem-768-avx2/LICENSE`.

## Asymmetric incomplete-NTT multiplication scheduling

The GCC-native AVX512 four-output encryption and three-output keygen
accumulators in `baby-mlkem.c` apply the asymmetric-multiplication principle
described in Section 4.2 of:

Becker, Hwang, Kannwischer, Yang, and Yang,
"Neon NTT: Faster Dilithium, Kyber, and Saber,"
https://eprint.iacr.org/2021/986.pdf

The known idea is to form the twiddle-weighted terms of an incomplete-NTT
operand once and reuse them across matrix-vector products. baby-mlkem adapts
that arithmetic observation to transient 32-coefficient ZMM blocks: encryption
shares factors from common `rhat` across three `u` rows and `v`, while
keygen shares factors from common `shat` across all three columns of `A^T*s`.

No source code from that implementation is copied or linked. The intrinsics
schedules and fixed-range reduction are repository-local, and the weighted
factors are generated in registers rather than stored in an expanded key,
persistent cache, or precomputed table. The underlying asymmetric-multiplication
idea is externally derived and is not claimed as independently invented here.

## Single-state AVX2 Keccak-f[1600]

The local keccakf1600_avx2.h implementation adapts the seven-vector state
layout and round schedule from the XKCP KeccakP-1600 AVX2 implementation:

https://github.com/XKCP/XKCP/blob/master/lib/low/KeccakP-1600/AVX2/KeccakP-1600-AVX2.s

That XKCP source was generated from CRYPTOGAMS keccak1600-avx2.pl by Andy
Polyakov. baby-mlkem does not link XKCP or CRYPTOGAMS; the adapted intrinsics
implementation is compiled directly into the local core.

For XKCP/lib/low/KeccakP-1600/AVX2/KeccakP-1600-AVX2.s and XKCP/lib/low/KeccakP-1600/AVX512/KeccakP-1600-AVX512.s (potentially used in libXKCP, UnitTests, Benchmarks and KeccakSum, depending on the target platform):

    Copyright (c) 2006-2017, CRYPTOGAMS by <appro@openssl.org>
    All rights reserved.

    Redistribution and use in source and binary forms, with or without
    modification, are permitted provided that the following conditions
    are met:

        *	Redistributions of source code must retain copyright notices,
        this list of conditions and the following disclaimer.

        *	Redistributions in binary form must reproduce the above
        copyright notice, this list of conditions and the following
        disclaimer in the documentation and/or other materials
        provided with the distribution.

        *	Neither the name of the CRYPTOGAMS nor the names of its
        copyright holder and contributors may be used to endorse or
        promote products derived from this software without specific
        prior written permission.

    ALTERNATIVELY, provided that this notice is retained in full, this
    product may be distributed under the terms of the GNU General Public
    License (GPL), in which case the provisions of the GPL apply INSTEAD OF
    those given above.

    THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDER AND CONTRIBUTORS
    "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
    LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
    A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
    OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
    SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
    LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
    DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
    THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
    (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
    OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

## Single-state AVX512VL Keccak and fixed-length SHA3-256

The compact single-state permutation in the repository-local
`sha3_256_1184_avx512vl.S` implementation adapts the register-per-lane Keccak
round schedule from Intel's AVX512VL implementation contributed to liboqs in
pull request 2167:

https://github.com/open-quantum-safe/liboqs/blob/3dca9c939c779c58ffa540f3f47ca099a1fa4b94/src/common/sha3/avx512vl_low/KeccakP-1600-AVX512VL.S

baby-mlkem does not link liboqs or an Intel object. The compact local core
narrows the single-state round body from YMM to XMM registers and exposes a
canonical-state permutation wrapper.

The fixed 1184-byte ML-KEM-768 public-key hash uses a separate generated
four-round core. It applies the order-four cyclic lane mapping described as
Algorithm 4 in the Keccak Team's *Keccak implementation overview*:

https://keccak.team/files/Keccak-implementation-3.2.pdf

The local generator derives the mapping variants and overwrite schedule; no
source code from that document is copied. The fixed path also specializes
absorb and padding and keeps the state in registers across all nine
permutations. Portions adapted from Intel's implementation remain covered by
Intel's MIT license:

    Copyright (c) 2025 Intel Corporation

    Permission is hereby granted, free of charge, to any person obtaining a copy
    of this software and associated documentation files (the "Software"), to deal
    in the Software without restriction, including without limitation the rights
    to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    copies of the Software, and to permit persons to whom the Software is
    furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all
    copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
    SOFTWARE.

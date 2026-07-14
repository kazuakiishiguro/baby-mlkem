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

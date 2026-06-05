#ifndef PARAMS_H
#define PARAMS_H

#define N 256
#define Q 3329

#define K 3
#define ETA1 2
#define ETA2 2
#define DU 10
#define DV 4

#define POLY_BYTES (N * 12 / 8)
#define EK_SIZE (K * POLY_BYTES + 32)
#define DK_PKE_SIZE (K * POLY_BYTES)
#define DK_SIZE (DK_PKE_SIZE + EK_SIZE + 32 + 32)
#define CT_U_SIZE (K * N * DU / 8)
#define CT_V_SIZE (N * DV / 8)
#define CT_SIZE (CT_U_SIZE + CT_V_SIZE)
#define SHARED_KEY_SIZE 32

#define NTT_INV_FACTOR 3303
#define ZETA_PRIMITIVE 17

#endif

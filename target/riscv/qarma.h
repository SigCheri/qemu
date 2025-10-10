#ifndef _QARMA_H
#define _QARMA_H

#include <stdint.h>

#define MAX_LENGTH 64
#define subcells sbox[sbox_use]
#define subcells_inv sbox_inv[sbox_use]

typedef unsigned long long int const_t;
typedef unsigned long long int tweak_t;
typedef unsigned long long int text_t;
typedef unsigned long long int qkey_t;
typedef unsigned char          cell_t;

void text2cell(cell_t* cell, text_t is);

text_t cell2text(cell_t* cell);

text_t pseudo_reflect(text_t is, qkey_t tk);

text_t forward(text_t is, qkey_t tk, int r);

text_t backward(text_t is, qkey_t tk, int r);

cell_t LFSR(cell_t x);

cell_t LFSR_inv(cell_t x);

qkey_t forward_update_key(qkey_t T);

qkey_t backward_update_key(qkey_t T);

text_t qarma64_enc(text_t plaintext, tweak_t tweak, qkey_t w0, qkey_t k0, int rounds);
text_t qarma64_dec(text_t plaintext, tweak_t tweak, qkey_t w0, qkey_t k0, int rounds);
#endif

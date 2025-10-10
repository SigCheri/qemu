#include "qemu/osdep.h"
#include "qemu/log.h"
#include "cpu.h"
#include "qemu/main-loop.h"
#include "exec/exec-all.h"
#include "exec/log.h"
#include "exec/helper-proto.h"
#include "qarma.h"
#ifndef TARGET_SIGCHERI
#error TARGET_SIGCHERI must be set
#endif

static void get_key_examine_priv(CPUArchState *env, uint64_t key_sel, target_ulong* keyl, target_ulong* keyh){
    target_ulong priv = env->priv;
    switch(key_sel){
        case 0:
            if(priv == 0)riscv_raise_exception(env, RISCV_EXCP_ILLEGAL_INST, GETPC());
            *keyl = env->mkey[0];
            *keyh = env->mkey[1];
            break;
        case 1:
            *keyl = env->skey[0];
            *keyh = env->skey[1];
            break;
        default:
            assert(false);
    }
}

target_ulong HELPER(encrypt_op)(CPUArchState *env, target_ulong plaintext, target_ulong tweak, uint64_t keysel, uint64_t mask){
    printf("\nencrypt_op: GETPC = %016lx\n", GETPC());
    plaintext &= (target_ulong)mask;
    target_ulong keyl, keyh;
    printf("encrypt_op: plaint = %016lx, tweak = %016lx, mask = %016lx\n", plaintext, tweak, mask);
    get_key_examine_priv(env, keysel, &keyl, &keyh);
    printf("encrypt_op: key = %c, keyl = %016lx, keyh = %016lx\n", keysel?'s':'m', keyl, keyh);
    target_ulong result = qarma64_enc(plaintext, tweak, keyl, keyh, 7);
    printf("encrypt_op: result = %016lx\n", result);
    return result;
}

target_ulong HELPER(decrypt_op)(CPUArchState *env, target_ulong secret, target_ulong tweak, uint64_t keysel, uint64_t mask){
    printf("\ndecrypt_op: GETPC = %016lx\n", GETPC());
    
    target_ulong keyl, keyh;
    printf("decrypt_op: secret = %016lx, tweak = %016lx, mask = %016lx\n", secret, tweak, mask);
    get_key_examine_priv(env, keysel, &keyl, &keyh);
    printf("decrypt_op: key = %c, keyl = %016lx, keyh = %016lx\n", keysel?'s':'m', keyl, keyh);
    target_ulong result = qarma64_dec(secret, tweak, keyl, keyh, 7);
    printf("decrypt_op: result = %016lx\n", result);
    if((result & (target_ulong)mask) == result){
        return result;
    }else{
        riscv_raise_exception(env, RISCV_EXCP_ILLEGAL_INST, GETPC());
    }
}


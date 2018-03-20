#include "cpuminer-config.h"
#include "algo-gate-api.h"

#include <string.h>
#include <stdint.h>

#include "algo/blake/sph_blake.h"
#include "algo/bmw/sph_bmw.h"
#include "algo/groestl/sph_groestl.h"
#include "algo/jh/sph_jh.h"
#include "algo/keccak/sph_keccak.h"
#include "algo/skein/sph_skein.h"
#include "algo/luffa/sph_luffa.h"
#include "algo/cubehash/sph_cubehash.h"
#include "algo/shavite/sph_shavite.h"
#include "algo/simd/sph_simd.h"
#include "algo/echo/sph_echo.h"

#ifndef NO_AES_NI
  #include "algo/groestl/aes_ni/hash-groestl.h"
  #include "algo/echo/aes_ni/hash_api.h"
#endif

#include "algo/luffa/sse2/luffa_for_sse2.h"
#include "algo/cubehash/sse2/cubehash_sse2.h"
#include "algo/simd/sse2/nist.h"
#include "algo/blake/sse2/blake.c"  
#include "algo/keccak/sse2/keccak.c"
#include "algo/bmw/sse2/bmw.c"
#include "algo/skein/sse2/skein.c"
#include "algo/jh/sse2/jh_sse2_opt64.h"

typedef struct {
    hashState_luffa         luffa;
    cubehashParam           cube;
    hashState_sd            simd;
    sph_shavite512_context  shavite;
#ifdef NO_AES_NI
    sph_groestl512_context  groestl;
    sph_echo512_context     echo;
#else
    hashState_echo          echo;
    hashState_groestl       groestl;
#endif
} x11r_ctx_holder;

x11r_ctx_holder x11r_ctx;

void init_x11r_ctx()
{
     init_luffa( &x11r_ctx.luffa, 512 );
     cubehashInit( &x11r_ctx.cube, 512, 16, 32 );
     sph_shavite512_init( &x11r_ctx.shavite );
     init_sd( &x11r_ctx.simd, 512 );
#ifdef NO_AES_NI
     sph_groestl512_init( &x11r_ctx.groestl );
     sph_echo512_init( &x11r_ctx.echo );
#else
     init_echo( &x11r_ctx.echo, 512 );
     init_groestl( &x11r_ctx.groestl, 64 );
#endif
}

static void x11r_hash( void *state, const void *input )
{
     unsigned char hash[128] __attribute__ ((aligned (32)));
     unsigned char hashbuf[128] __attribute__ ((aligned (16)));

     char data_str[161], hash_str[65], target_str[65];
     unsigned char out[64];
     sph_u64 hashctA;
     sph_u64 hashctB;
     x11r_ctx_holder ctx;
     memcpy( &ctx, &x11r_ctx, sizeof(x11r_ctx) );
     size_t hashptr;
//    bin2hex(hash_str, (unsigned char *)hash, 80);

/*     printf("\n\ninit hash: ");unsigned char *p = input;
      int len = 80;
	for (int i = 0; i < len; i++) printf("%02x", (unsigned int) p[i]);
	printf("\n");
*/
//     applog(LOG_DEBUG, "\n\ninit hash: %s", hash_str);

      sph_bmw512_context       ctx_bmw;
      sph_blake512_context     ctx_blake;
      sph_skein512_context     ctx_skein;
      sph_groestl512_context   ctx_groestl;
      sph_keccak512_context    ctx_keccak;
      sph_jh512_context        ctx_jh;
      sph_cubehash512_context  ctx_cubehash;
      sph_luffa512_context     ctx_luffa;
      sph_simd512_context      ctx_simd;
      sph_echo512_context      ctx_echo;
      sph_shavite512_context   ctx_shavite;

      sph_bmw512_init(&ctx_bmw);
      sph_bmw512 (&ctx_bmw, input, 80);
      sph_bmw512_close(&ctx_bmw, hashbuf);

//      bin2hex(hash_str, (unsigned char *)hashbuf, 64);
//      applog(LOG_DEBUG, "hash after bmw: %s", hash_str);

      sph_blake512_init(&ctx_blake);
      sph_blake512 (&ctx_blake, hashbuf, 64);
      sph_blake512_close(&ctx_blake, hashbuf);

//      bin2hex(hash_str, (unsigned char *)hashbuf, 64);
//      applog(LOG_DEBUG, "hash after blk: %s", hash_str);

      sph_skein512_init(&ctx_skein);
      sph_skein512 (&ctx_skein, hashbuf, 64);
      sph_skein512_close(&ctx_skein, hashbuf);
  
//      bin2hex(hash_str, (unsigned char *)hashbuf, 64);
//      applog(LOG_DEBUG, "hash after skn: %s", hash_str);


      sph_groestl512_init(&ctx_groestl);
      sph_groestl512 (&ctx_groestl, hashbuf, 64);
      sph_groestl512_close(&ctx_groestl, hashbuf);

//     bin2hex(hash_str, (unsigned char *)hashbuf, 64);
//     applog(LOG_DEBUG, "hash after groest: %s", hash_str);

     sph_keccak512_init(&ctx_keccak);
     sph_keccak512 (&ctx_keccak, hashbuf, 64);
     sph_keccak512_close(&ctx_keccak, hashbuf);

     sph_jh512_init(&ctx_jh);
     sph_jh512 (&ctx_jh, hashbuf, 64);
     sph_jh512_close(&ctx_jh, hashbuf);

     sph_cubehash512_init(&ctx_cubehash);
     sph_cubehash512 (&ctx_cubehash, hashbuf, 64);
     sph_cubehash512_close(&ctx_cubehash, hashbuf);

//     bin2hex(hash_str, (unsigned char *)hashbuf, 64);
//     applog(LOG_DEBUG, "hash after cube: %s", hash_str);


   sph_luffa512_init(&ctx_luffa);
   sph_luffa512 (&ctx_luffa, hashbuf, 64);
   sph_luffa512_close(&ctx_luffa, hashbuf);

   sph_simd512_init(&ctx_simd);
   sph_simd512(&ctx_simd, hashbuf, 64);
   sph_simd512_close(&ctx_simd, hashbuf);

   sph_echo512_init(&ctx_echo);
   sph_echo512 (&ctx_echo, hashbuf, 64);
   sph_echo512_close(&ctx_echo, hashbuf);

   sph_shavite512_init(&ctx_shavite);
   sph_shavite512 (&ctx_shavite, hashbuf, 64);
   sph_shavite512_close(&ctx_shavite, hash+64);

//     bin2hex(hash_str, (unsigned char *)hash+64, 64);
//     applog(LOG_DEBUG, "hash after shavite: %s", hash_str);

//     bin2hex(hash_str, (unsigned char *)hash+64, 32);
//     applog(LOG_DEBUG, "hash out: %s", hash_str);


//        asm volatile ("emms");
     memcpy( state, hash+64, 32 );
}

int scanhash_x11r( int thr_id, struct work *work, uint32_t max_nonce,
                  uint64_t *hashes_done )
{
        uint32_t endiandata[20] __attribute__((aligned(64)));
        uint32_t hash64[8] __attribute__((aligned(64)));
        uint32_t *pdata = work->data;
        uint32_t *ptarget = work->target;
	uint32_t n = pdata[19] - 1;
	const uint32_t first_nonce = pdata[19];
	const uint32_t Htarg = ptarget[7];
        uint64_t htmax[] = {
                0,
                0xF,
                0xFF,
                0xFFF,
                0xFFFF,
                0x10000000
        };
        uint32_t masks[] = {
                0xFFFFFFFF,
                0xFFFFFFF0,
                0xFFFFFF00,
                0xFFFFF000,
                0xFFFF0000,
                0
        };

        // big endian encode 0..18 uint32_t, 64 bits at a time
        swab32_array( endiandata, pdata, 20 );

        for (int m=0; m < 6; m++) 
          if (Htarg <= htmax[m])
          {
            uint32_t mask = masks[m];
            do
            {
              pdata[19] = ++n;
              be32enc( &endiandata[19], n );
              x11r_hash( hash64, &endiandata );
              if ( ( hash64[7] & mask ) == 0 )
              {
                 if ( fulltest( hash64, ptarget ) )
                 {
                    *hashes_done = n - first_nonce + 1;
                    return true;
                 }
              }
            } while ( n < max_nonce && !work_restart[thr_id].restart );
          }

        *hashes_done = n - first_nonce + 1;
        pdata[19] = n;
        return 0;
}

bool register_x11r_algo( algo_gate_t* gate )
{
  gate->optimizations = SSE2_OPT | AES_OPT | AVX_OPT | AVX2_OPT;
  init_x11r_ctx();
  gate->scanhash  = (void*)&scanhash_x11r;
  gate->hash      = (void*)&x11r_hash;
  gate->get_max64 = (void*)&get_max64_0x3ffff;
  return true;
};


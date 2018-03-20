#include "algo-gate-api.h"

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

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
    sph_shavite512_context  shavite;
    sph_skein512_context     skein;
#ifdef NO_AES_NI
    sph_groestl512_context  groestl;
    sph_echo512_context     echo;
#else
     hashState_echo          echo;
     hashState_groestl       groestl;
#endif
     hashState_luffa         luffa;
     cubehashParam           cube;
     hashState_sd            simd;
} c11r_ctx_holder;

c11r_ctx_holder c11r_ctx __attribute__ ((aligned (64)));

void init_c11r_ctx()
{
     init_luffa( &c11r_ctx.luffa, 512 );
     cubehashInit( &c11r_ctx.cube, 512, 16, 32 );
     sph_shavite512_init( &c11r_ctx.shavite );
     init_sd( &c11r_ctx.simd, 512 );
#ifdef NO_AES_NI
     sph_groestl512_init( &c11r_ctx.groestl );
     sph_echo512_init( &c11r_ctx.echo );
#else
     init_echo( &c11r_ctx.echo, 512 );
     init_groestl( &c11r_ctx.groestl, 64 );
#endif
}

void c11rhash( void *output, const void *input )
{
        unsigned char hash[128] _ALIGN(64); // uint32_t hashA[16], hashB[16];
//	uint32_t _ALIGN(64) hash[16];

     c11r_ctx_holder ctx __attribute__ ((aligned (64)));
     memcpy( &ctx, &c11r_ctx, sizeof(c11r_ctx) );

     size_t hashptr;
     char data_str[161], hash_str[65], target_str[65];

     unsigned char hashbuf[128];
     sph_u64 hashctA;
     sph_u64 hashctB;

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
	int len = 80;
      sph_bmw512_init(&ctx_bmw);
      sph_bmw512 (&ctx_bmw, input, len);
      sph_bmw512_close(&ctx_bmw, hashbuf);

      bin2hex(hash_str, (unsigned char *)hashbuf, 64);
      applog(LOG_DEBUG, "c11rhash after bmw: %s", hash_str);

      sph_blake512_init(&ctx_blake);
      sph_blake512 (&ctx_blake, hashbuf, 64);
      sph_blake512_close(&ctx_blake, hashbuf);

      bin2hex(hash_str, (unsigned char *)hashbuf, 64);
      applog(LOG_DEBUG, "c11rhash after blk: %s", hash_str);

      sph_skein512_init(&ctx_skein);
      sph_skein512 (&ctx_skein, hashbuf, 64);
      sph_skein512_close(&ctx_skein, hashbuf);
  
      bin2hex(hash_str, (unsigned char *)hashbuf, 64);
      applog(LOG_DEBUG, "c11rhash after skn: %s", hash_str);


      sph_groestl512_init(&ctx_groestl);
      sph_groestl512 (&ctx_groestl, hashbuf, 64);
      sph_groestl512_close(&ctx_groestl, hashbuf);

     bin2hex(hash_str, (unsigned char *)hashbuf, 64);
     applog(LOG_DEBUG, "c11rhash after groest: %s", hash_str);

     sph_keccak512_init(&ctx_keccak);
     sph_keccak512 (&ctx_keccak, hashbuf, 64);
     sph_keccak512_close(&ctx_keccak, hashbuf);

     sph_jh512_init(&ctx_jh);
     sph_jh512 (&ctx_jh, hashbuf, 64);
     sph_jh512_close(&ctx_jh, hashbuf);

     sph_cubehash512_init(&ctx_cubehash);
     sph_cubehash512 (&ctx_cubehash, hashbuf, 64);
     sph_cubehash512_close(&ctx_cubehash, hashbuf);

     bin2hex(hash_str, (unsigned char *)hashbuf, 64);
     applog(LOG_DEBUG, "hash after cube: %s", hash_str);


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

     bin2hex(hash_str, (unsigned char *)hash+64, 64);
     applog(LOG_DEBUG, "c11rhash after shavite: %s", hash_str);

 



        memcpy(output, hash+64, 32);
}

int scanhash_c11r( int thr_id, struct work *work, uint32_t max_nonce,
                  uint64_t *hashes_done )
{
        uint32_t endiandata[20] __attribute__((aligned(64)));
        uint32_t hash[8] __attribute__((aligned(64)));
        uint32_t *pdata = work->data;
        uint32_t *ptarget = work->target;
	const uint32_t first_nonce = pdata[19];
        const uint32_t Htarg = ptarget[7];
	uint32_t nonce = first_nonce;
	volatile uint8_t *restart = &(work_restart[thr_id].restart);

	if (opt_benchmark)
		((uint32_t*)ptarget)[7] = 0x0cff;

        swab32_array( endiandata, pdata, 20 );

	do
        {
		be32enc( &endiandata[19], nonce );
		c11rhash( hash, endiandata );
		if ( hash[7] <= Htarg && fulltest(hash, ptarget) )
                {
			pdata[19] = nonce;
			*hashes_done = pdata[19] - first_nonce;
			return 1;
		}
		nonce++;
	} while ( nonce < max_nonce && !(*restart) );
	pdata[19] = nonce;
	*hashes_done = pdata[19] - first_nonce + 1;
	return 0;
}

bool register_c11r_algo( algo_gate_t* gate )
{
  gate->optimizations = SSE2_OPT | AES_OPT | AVX_OPT | AVX2_OPT;
  init_c11r_ctx();
  gate->scanhash  = (void*)&scanhash_c11r;
  gate->hash      = (void*)&c11rhash;
  gate->get_max64 = (void*)&get_max64_0x3ffff;
  return true;
};


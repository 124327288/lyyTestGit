#ifndef _ADDFORECC_H
#define _ADDFORECC_H


#include "time.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <limits.h>

#ifdef LIBEAY32_EXPORTS
#define  EXPORT __declspec(dllexport)
#else
#define EXPORT __declspec(dllimport)
#endif

#define OPENSSL_VERSION_TEXT "OpenSSL 0.9.8g 19 Oct 2007"
#define OPENSSL_VERSION_PTEXT " part of " OPENSSL_VERSION_TEXT
// #ifdef THIRTY_TWO_BIT
// #ifdef BN_LLONG
# if defined(OPENSSL_SYS_WIN32) && !defined(__GNUC__)
#  define BN_ULLONG	unsigned __int64
# else
#  define BN_ULLONG	unsigned long long
# endif
#endif
#define BN_ULONG	unsigned long
#define BN_LONG		long
#define BN_BITS		64
#define BN_BYTES	4
#define BN_BITS2	32
#define BN_BITS4	16
#ifdef OPENSSL_SYS_WIN32
/* VC++ doesn't like the LL suffix */
#define BN_MASK		(0xffffffffffffffffL)
#else
#define BN_MASK		(0xffffffffffffffffLL)
#endif
#define BN_MASK2	(0xffffffffL)
#define BN_MASK2l	(0xffff)
#define BN_MASK2h1	(0xffff8000L)
#define BN_MASK2h	(0xffff0000L)
#define BN_TBIT		(0x80000000L)
#define BN_DEC_CONV	(1000000000L)
#define BN_DEC_FMT1	"%lu"
#define BN_DEC_FMT2	"%09lu"
#define BN_DEC_NUM	9
//#endif
#define BN_FLG_CONSTTIME 0x04 
#define BN_F_BN_CTX_NEW			106
#define ERR_R_FATAL				64
#define ERR_R_MALLOC_FAILURE (1|ERR_R_FATAL)
#define NULL ((void *)0)
#define BN_CTX_POOL_SIZE 16
#define NULL ((void *)0)
#define CRYPTO_MEM_CHECK_OFF 0x0 
#define CRYPTO_MEM_CHECK_ON 0x1 
#define CRYPTO_LOCK_MALLOC 20
#define CRYPTO_MEM_CHECK_ENABLE 0x2 
#define CRYPTO_LOCK 1
#define CRYPTO_WRITE 8
#define CRYPTO_READ 4
#define CRYPTO_UNLOCK 2
#define V_CRYPTO_MDEBUG_THREAD 0x2 
#define V_CRYPTO_MDEBUG_TIME 0x1 
#define BN_F_BN_CTX_START 129
#define BN_R_TOO_MANY_TEMPORARY_VARIABLES 109
#define BN_F_BN_CTX_GET 116
#define ERR_LIB_BN 3
#define BN_CTX_START_FRAMES 32
#define BN_FLG_STATIC_DATA	0x02
#define BN_FLG_MALLOCED		0x01
#define BN_FLG_FREE 0x8000 
#define BN_F_BN_EXPAND_INTERNAL 120
#define BN_R_EXPAND_ON_STATIC_BIGNUM_DATA 105
#define BN_R_BIGNUM_TOO_LONG 114
#define BN_BITS4	16
#define CRYPTO_MEM_CHECK_DISABLE 0x3 
#define CRYPTO_MEM_CHECK_ENABLE 0x2 
#define MIN_NODES 16
#define LH_LOAD_MULT 256

#define LBITS(a) ((a)&BN_MASK2l)
#define HBITS(a) (((a)>>BN_BITS4)&BN_MASK2l)
#define L2HBITS(a) (((a)<<BN_BITS4)&BN_MASK2)
#define mul_add(r,a,bl,bh,c) { BN_ULONG l,h; h= (a); l=LBITS(h); h=HBITS(h); mul64(l,h,(bl),(bh)); l=(l+(c))&BN_MASK2; if (l < (c)) h++; (c)=(r); l=(l+(c))&BN_MASK2; if (l < (c)) h++; (c)=h&BN_MASK2; (r)=l; }
#define mul(r,a,bl,bh,c) { BN_ULONG l,h; h= (a); l=LBITS(h); h=HBITS(h); mul64(l,h,(bl),(bh)); l+=(c); if ((l&BN_MASK2) < (c)) h++; (c)=h&BN_MASK2; (r)=l&BN_MASK2; }
#define sqr64(lo,ho,in) { BN_ULONG l,h,m; h=(in); l=LBITS(h); h=HBITS(h); m =(l)*(h); l*=l; h*=h; h+=(m&BN_MASK2h1)>>(BN_BITS4-1); m =(m&BN_MASK2l)<<(BN_BITS4+1); l=(l+m)&BN_MASK2; if (l < m) h++; (lo)=l; (ho)=h; }
#define mul64(l,h,bl,bh) { BN_ULONG m,m1,lt,ht; lt=l; ht=h; m =(bh)*(lt); lt=(bl)*(lt); m1=(bl)*(ht); ht =(bh)*(ht); m=(m+m1)&BN_MASK2; if (m < m1) ht+=L2HBITS((BN_ULONG)1); ht+=HBITS(m); m1=L2HBITS(m); lt=(lt+m1)&BN_MASK2; if (lt < m1) ht++; (l)=lt; (h)=ht; }



struct bignum_st
{
	BN_ULONG *d;	
	int top;
	int dmax;
	int neg;
	int flags;
};

typedef struct bignum_st BIGNUM;

typedef struct bignum_pool_item
{
	BIGNUM vals[BN_CTX_POOL_SIZE];
	struct bignum_pool_item *prev, *next;
} BN_POOL_ITEM;


typedef struct bignum_pool
{
	BN_POOL_ITEM *head, *current, *tail;
	unsigned used, size;
}BN_POOL;

typedef struct bignum_ctx_stack
{
	unsigned int *indexes;
	unsigned int depth, size;
} BN_STACK;

struct bignum_ctx
{
	BN_POOL pool;
	BN_STACK stack;
	unsigned int used;
	int err_stack;
	int too_many;
};
typedef struct bignum_ctx BN_CTX;

typedef struct app_mem_info_st
{	
	unsigned long thread;
	const char *file;
	int line;
	const char *info;
	struct app_mem_info_st *next; 
	int references;
} APP_INFO;

typedef struct mem_st
{
	void *addr;
	int num;
	const char *file;
	int line;
	unsigned long thread;
	unsigned long order;
	time_t time;
	APP_INFO *app_info;
} MEM;

typedef struct lhash_node_st
{
	void *data;
	struct lhash_node_st *next;
#ifndef OPENSSL_NO_HASH_COMP
	unsigned long hash;
#endif
} LHASH_NODE;

typedef int (*LHASH_COMP_FN_TYPE)(const void *, const void *);
typedef unsigned long (*LHASH_HASH_FN_TYPE)(const void *);
typedef struct lhash_st
{
	LHASH_NODE **b;
	LHASH_COMP_FN_TYPE comp;
	LHASH_HASH_FN_TYPE hash;
	unsigned int num_nodes;
	unsigned int num_alloc_nodes;
	unsigned int p;
	unsigned int pmax;
	unsigned long up_load; 
	unsigned long down_load; 
	unsigned long num_items;
	
	unsigned long num_expands;
	unsigned long num_expand_reallocs;
	unsigned long num_contracts;
	unsigned long num_contract_reallocs;
	unsigned long num_hash_calls;
	unsigned long num_comp_calls;
	unsigned long num_insert;
	unsigned long num_replace;
	unsigned long num_delete;
	unsigned long num_no_delete;
	unsigned long num_retrieve;
	unsigned long num_retrieve_miss;
	unsigned long num_hash_comps;
	
	int error;
} LHASH;


// void *lh_delete(LHASH *lh, const void *data);
int CRYPTO_mem_ctrl(int mode);
// #define MemCheck_on() CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ENABLE)
// int CRYPTO_is_mem_check_on(void);
// unsigned long CRYPTO_thread_id(void);
void CRYPTO_dbg_malloc(void *addr, int num, const char *file, int line,
					   int before_p);
void CRYPTO_lock(int mode, int type,const char *file,int line);
void CRYPTO_dbg_free(void *addr,int before_p);
// #define is_MemCheck_on() CRYPTO_is_mem_check_on()
#define MemCheck_off() CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_DISABLE)
void *CRYPTO_realloc(void *addr,int num, const char *file, int line);
#define OPENSSL_realloc(addr,num) CRYPTO_realloc((char *)addr,(int)num,__FILE__,__LINE__)

void CRYPTO_dbg_realloc(void *addr1, void *addr2, int num,
						const char *file, int line, int before_p);

void (*realloc_debug_func)(void *,void *,int,const char *,int,int);

void *(*realloc_func)(void *, size_t);


void *default_realloc_ex(void *str, size_t num,
								const char *file, int line);



void *(*realloc_ex_func)(void *, size_t, const char *file, int line);


void BN_POOL_init(BN_POOL *);
void BN_POOL_finish(BN_POOL *);

#ifndef OPENSSL_NO_DEPRECATED
void BN_POOL_reset(BN_POOL *);
#endif

BIGNUM * BN_POOL_get(BN_POOL *);
void BN_POOL_release(BN_POOL *, unsigned int);
void BN_STACK_init(BN_STACK *);
void BN_STACK_finish(BN_STACK *);

#ifndef OPENSSL_NO_DEPRECATED
void BN_STACK_reset(BN_STACK *);
#endif

int	BN_STACK_push(BN_STACK *, unsigned int);
unsigned int BN_STACK_pop(BN_STACK *);
void BN_clear_free(BIGNUM *a);


#ifndef OPENSSL_NO_LOCKING
#ifndef CRYPTO_w_lock
#define CRYPTO_w_lock(type)	\
CRYPTO_lock(CRYPTO_LOCK|CRYPTO_WRITE,type,__FILE__,__LINE__)
#define CRYPTO_w_unlock(type)	\
CRYPTO_lock(CRYPTO_UNLOCK|CRYPTO_WRITE,type,__FILE__,__LINE__)
#define CRYPTO_r_lock(type)	\
CRYPTO_lock(CRYPTO_LOCK|CRYPTO_READ,type,__FILE__,__LINE__)
#define CRYPTO_r_unlock(type)	\
CRYPTO_lock(CRYPTO_UNLOCK|CRYPTO_READ,type,__FILE__,__LINE__)
#define CRYPTO_add(addr,amount,type)	\
CRYPTO_add_lock(addr,amount,type,__FILE__,__LINE__)
#endif
#else
#define CRYPTO_w_lock(a)
#define CRYPTO_w_unlock(a)
#define CRYPTO_r_lock(a)
#define CRYPTO_r_unlock(a)
#define CRYPTO_add(a,b,c)	((*(a))+=(b))
#endif

#define OPENSSL_free(addr) CRYPTO_free(addr)
#define OPENSSL_malloc(num)	CRYPTO_malloc((int)num,__FILE__,__LINE__)
// #define BNerr(f,r)   ERR_PUT_error(ERR_LIB_BN,(f),(r),__FILE__,__LINE__)

void OPENSSL_cleanse(void *ptr, size_t len);


void *CRYPTO_malloc(int num, const char *file, int line);
void CRYPTO_free(void *);


#define BN_set_flags(b,n)	((b)->flags|=(n))
#define BN_get_flags(b,n)	((b)->flags&(n))

#define bn_clear_top2max(a)


//#endif


BIGNUM *bn_expand2(BIGNUM *a, int words);
BN_ULONG bn_add_words(BN_ULONG *rp, const BN_ULONG *ap, const BN_ULONG *bp,int num);
EXPORT void BN_CTX_start(BN_CTX *ctx);
void BN_init(BIGNUM *);
int BN_add(BIGNUM *r, const BIGNUM *a, const BIGNUM *b);
int BN_uadd(BIGNUM *r, const BIGNUM *a, const BIGNUM *b);
int BN_sub(BIGNUM *r, const BIGNUM *a, const BIGNUM *b);
int BN_usub(BIGNUM *r, const BIGNUM *a, const BIGNUM *b);
void bn_sqr_normal(BN_ULONG *r, const BN_ULONG *a, int n, BN_ULONG *tmp);

int BN_sqr(BIGNUM *r, const BIGNUM *a,BN_CTX *ctx);
void bn_sqr_words(BN_ULONG *rp, const BN_ULONG *ap, int num);
int BN_mul(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, BN_CTX *ctx);
#define BN_mod(rem,m,d,ctx) BN_div(NULL,(rem),(m),(d),(ctx))
int BN_nnmod(BIGNUM *r, const BIGNUM *m, const BIGNUM *d, BN_CTX *ctx);
BN_ULONG bn_mul_add_words(BN_ULONG *rp, const BN_ULONG *ap, int num, BN_ULONG w);
void bn_sqr_words(BN_ULONG *rp, const BN_ULONG *ap, int num);
BN_ULONG bn_mul_words(BN_ULONG *rp, const BN_ULONG *ap, int num, BN_ULONG w);
int BN_div(BIGNUM *dv, BIGNUM *rem, const BIGNUM *m, const BIGNUM *d, BN_CTX *ctx);

EXPORT int	BN_bn2bin(const BIGNUM *a, unsigned char *to);
EXPORT int	BN_cmp(const BIGNUM *a, const BIGNUM *b);

EXPORT int BN_mod_add(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, const BIGNUM *m, BN_CTX *ctx);
EXPORT int BN_mod_sub(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, const BIGNUM *m, BN_CTX *ctx);
EXPORT int BN_mod_mul(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, const BIGNUM *m, BN_CTX *ctx);
EXPORT int BN_mod_sqr(BIGNUM *r, const BIGNUM *a, const BIGNUM *m, BN_CTX *ctx);
int BN_ucmp(const BIGNUM *a, const BIGNUM *b);
BIGNUM *BN_dup(const BIGNUM *a);
int BN_num_bits_word(BN_ULONG);
int BN_num_bits(const BIGNUM *a);

int BN_lshift(BIGNUM *r, const BIGNUM *a, int n);
int BN_rshift(BIGNUM *r, const BIGNUM *a, int n);
int BN_rshift1(BIGNUM *r, const BIGNUM *a);
int BN_lshift1(BIGNUM *r, const BIGNUM *a);

int BN_mul_word(BIGNUM *a, BN_ULONG w);
int BN_is_bit_set(const BIGNUM *a, int n);

BIGNUM *BN_new(void);
void BN_free(BIGNUM *a);

#ifdef LIBEAY32_EXPORTS
#define  EXPORT __declspec(dllexport)
#else
#define EXPORT __declspec(dllimport)
#endif


EXPORT BN_CTX *BN_CTX_new(void); //
EXPORT BIGNUM *BN_CTX_get(BN_CTX *ctx); ///
// void BN_CTX_start(BN_CTX *ctx);
EXPORT BIGNUM *BN_bin2bn(const unsigned char *s,int len,BIGNUM *ret); //
EXPORT BIGNUM *BN_mod_inverse(BIGNUM *ret, const BIGNUM *a, const BIGNUM *n,BN_CTX *ctx);
EXPORT BIGNUM *BN_copy(BIGNUM *a, const BIGNUM *b);
EXPORT void BN_CTX_end(BN_CTX *ctx); //
EXPORT void BN_CTX_free(BN_CTX *c);
EXPORT int BN_set_word(BIGNUM *a, BN_ULONG w);
BIGNUM *BN_mod_inverse_no_branch(BIGNUM *in,
        const BIGNUM *a, const BIGNUM *n, BN_CTX *ctx);
int BN_div_no_branch(BIGNUM *dv, BIGNUM *rm, const BIGNUM *num, const BIGNUM *divisor, BN_CTX *ctx);
BN_ULONG bn_div_words(BN_ULONG h, BN_ULONG l, BN_ULONG d);
BN_ULONG bn_sub_words(BN_ULONG *rp, const BN_ULONG *ap, const BN_ULONG *bp,int num);
void bn_mul_normal(BN_ULONG *r, BN_ULONG *a, int na, BN_ULONG *b, int nb);
int BN_rshift(BIGNUM *r, const BIGNUM *a, int n);
#define BN_with_flags(dest,b,n) ((dest)->d=(b)->d, (dest)->top=(b)->top, (dest)->dmax=(b)->dmax, (dest)->neg=(b)->neg, (dest)->flags=(((dest)->flags & BN_FLG_MALLOCED) | ((b)->flags & ~BN_FLG_MALLOCED) | BN_FLG_STATIC_DATA | (n)))


#ifdef BN_DEBUG

#include <assert.h>

#ifdef BN_DEBUG_RAND
/* To avoid "make update" cvs wars due to BN_DEBUG, use some tricks */
#ifndef RAND_pseudo_bytes
int RAND_pseudo_bytes(unsigned char *buf,int num);
#define BN_DEBUG_TRIX
#endif
#define bn_pollute(a) \
	do { \
	const BIGNUM *_bnum1 = (a); \
	if(_bnum1->top < _bnum1->dmax) { \
	unsigned char _tmp_char; \
/* We cast away const without the compiler knowing, any \
* *genuinely* constant variables that aren't mutable \
* wouldn't be constructed with top!=dmax. */ \
BN_ULONG *_not_const; \
memcpy(&_not_const, &_bnum1->d, sizeof(BN_ULONG*)); \
RAND_pseudo_bytes(&_tmp_char, 1); \
memset((unsigned char *)(_not_const + _bnum1->top), _tmp_char, \
	   (_bnum1->dmax - _bnum1->top) * sizeof(BN_ULONG)); \
	} \
	} while(0)
#ifdef BN_DEBUG_TRIX
#undef RAND_pseudo_bytes
#endif
#else
#define bn_pollute(a)
#endif
#define bn_check_top(a) \
	do { \
	const BIGNUM *_bnum2 = (a); \
	if (_bnum2 != NULL) { \
	assert((_bnum2->top == 0) || \
				(_bnum2->d[_bnum2->top - 1] != 0)); \
				bn_pollute(_bnum2); \
	} \
	} while(0)
	
#define bn_fix_top(a)		bn_check_top(a)
	
#else /* !BN_DEBUG */
	
#define bn_pollute(a)
#define bn_check_top(a)
#define bn_fix_top(a)		bn_correct_top(a)
	
#endif
	
#define bn_correct_top(a) \
	{ \
	BN_ULONG *ftl; \
	if ((a)->top > 0) \
	{ \
	for (ftl= &((a)->d[(a)->top-1]); (a)->top > 0; (a)->top--) \
	if (*(ftl--)) break; \
} \
	bn_pollute(a); \
}

#define bn_expand(a,bits) ((((((bits+BN_BITS2-1))/BN_BITS2)) <= (a)->dmax)?\
	(a):bn_expand2((a),(bits+BN_BITS2-1)/BN_BITS2))
#define bn_wexpand(a,words) (((words) <= (a)->dmax)?(a):bn_expand2((a),(words)))
#define BN_num_bytes(a) ((BN_num_bits(a)+7)/8)

#define BN_is_zero(a)       ((a)->top == 0)
#ifdef OPENSSL_NO_DEPRECATED
#define BN_zero(a)	BN_zero_ex(a)
#else
#define BN_zero(a)	(BN_set_word((a),0))
#endif

#define BN_abs_is_word(a,w) ((((a)->top == 1) && ((a)->d[0] == (BN_ULONG)(w))) || (((w) == 0) && ((a)->top == 0)))
#define BN_get_flags(b,n) ((b)->flags&(n))

#define BN_one(a) (BN_set_word((a),1))

#define BN_is_word(a,w) (BN_abs_is_word((a),(w)) && (!(w) || !(a)->neg))
#define BN_is_odd(a) (((a)->top > 0) && ((a)->d[0] & 1))
#define BN_is_one(a) (BN_abs_is_word((a),1) && !(a)->neg)


/*
 * Licensed Materials - Property of IBM
 *
 * trousers - An open source TCG Software Stack
 *
 * (C) Copyright International Business Machines Corp. 2006
 *
 */

#ifndef BI_OPENSSL_
#define BI_OPENSSL_

#ifdef WIN32
#include "bi.h"
#endif

#include <openssl/bn.h>
#include <openssl/engine.h>

typedef struct bignum_st bi_t[1];

typedef struct bignum_st *bi_ptr;

extern BN_CTX *context;


INLINE_DECL bi_ptr bi_new(bi_ptr result);

/* create a big integer pointer */
INLINE_DECL bi_ptr bi_new_ptr(void);

/* free resources allocated to the big integer <i> */
INLINE_DECL void bi_free(const bi_ptr i);

/* free resources allocated to the big integer pointer <i> */
INLINE_DECL void bi_free_ptr(const bi_ptr i);

/* <result> := result++ */
INLINE_DECL bi_ptr bi_inc(bi_ptr result);

/* <result> := result-- */
INLINE_DECL bi_ptr bi_dec(bi_ptr result);

/* return the current number of bits of the number */
INLINE_DECL long bi_length( const bi_ptr res);

/***********************************************************************************
	BASIC MATH OPERATION
*************************************************************************************/
/* <result> := - <result> */
INLINE_DECL bi_ptr bi_negate( bi_ptr result);

INLINE_DECL bi_ptr bi_mul_si( bi_ptr result, const bi_ptr i, const long n);

/*  <result> := <i> * <n>   */
INLINE_DECL bi_ptr bi_mul( bi_ptr result, const bi_ptr i, const bi_ptr n);

INLINE_DECL bi_ptr bi_add_si( bi_ptr result, const bi_ptr i, const long n);

/*  <result> := <i> + <n>  */
INLINE_DECL bi_ptr bi_add( bi_ptr result, const bi_ptr i, const bi_ptr n);

/*  <result> := <i> - <n>   */
INLINE_DECL bi_ptr bi_sub_si( bi_ptr result, const bi_ptr i, const long n);

/*  <result> := <i> - <n>  */
INLINE_DECL bi_ptr bi_sub( bi_ptr result, const bi_ptr i, const bi_ptr n);

/*  <result> := ( <g> ^ <e> ) mod <m>  */
INLINE_DECL bi_ptr bi_mod_exp( bi_ptr result, const bi_ptr g, const bi_ptr e, const bi_ptr m);

/* set <result> by the division of <i> by the long <n>  */
/*  <result> := <i> / <n>   */
INLINE_DECL bi_ptr bi_div_si( bi_ptr result, const bi_ptr i, const long n);

/*  <result> := <i> / <n>   */
INLINE_DECL bi_ptr bi_div( bi_ptr result, const bi_ptr i, const bi_ptr n);

/***********************************************************************************
	COMPARAISON
*************************************************************************************/
/*  n1<n2   return negative value
 *  n1 = n2 return 0
 *  n1>n2   return positive value
*/
INLINE_DECL int bi_cmp( const bi_ptr n1, const bi_ptr n2);

/*  n1<n2   return negative value
 *  n1 = n2 return 0
 *  n1>n2   return positive value
*/
INLINE_DECL int bi_cmp_si( const bi_ptr n1, const int n2);

/*  n1 == n2   return 1 (true)
 *  else return 0
*/
INLINE_DECL int bi_equals( const bi_ptr n1, const bi_ptr n2);

/*  n1 == n2   return 1 (true)
 *  else return 0
*/
INLINE_DECL int bi_equals_si( const bi_ptr n1, const int n2);

/***********************************************************************************
	CONVERSIONS
*************************************************************************************/

INLINE_DECL char *bi_2_hex_char(const bi_ptr i);

INLINE_DECL char *bi_2_dec_char(const bi_ptr i);

INLINE_DECL bi_ptr bi_set( bi_ptr result, const bi_ptr value);

INLINE_DECL bi_ptr bi_set_as_hex( bi_ptr result, const char *value);

INLINE_DECL bi_ptr bi_set_as_dec( bi_ptr result, const char *value);

/* set <i> with the value represented by unsigned int <value> */
 /*    <i> := <value>          */
INLINE_DECL bi_ptr bi_set_as_si( bi_ptr result, const int value);

/* return (long)bi_t  */
INLINE_DECL long bi_get_si(const bi_ptr i);

/* return the size of a network byte order representation of <i>  */
INLINE_DECL long bi_nbin_size(const bi_ptr i);

/* return a BYTE *  in network byte order - big endian - and update the length <length>  */
INLINE_DECL unsigned char *bi_2_nbin( int *length, const bi_ptr i);

/* return a BYTE * - in network byte order -  and update the length <length>  */
/* different from bi_2_nbin: you should reserve enough memory for the storage */
INLINE_DECL void bi_2_nbin1( int *length, unsigned char *buffer, const bi_ptr i);

/* return a bi_ptr that correspond to the big endian encoded BYTE array of length <n_length> */
INLINE_DECL bi_ptr bi_set_as_nbin( const unsigned long length, const unsigned char *buffer);

/* convert a bi to a openssl BIGNUM struct */
INLINE_DECL BIGNUM *bi_2_BIGNUM( const bi_ptr i);

/* set <i> with the value represented by the given openssl BIGNUM struct */
INLINE_DECL bi_ptr bi_set_as_BIGNUM( bi_ptr i, BIGNUM *bn);

/***********************************************************************************
	BITS OPERATION
*************************************************************************************/
/* set the bit to 1 */
INLINE_DECL bi_ptr bi_setbit(bi_ptr result, const int bit);

/* <result> := <i> << <n> */
INLINE_DECL bi_ptr bi_shift_left( bi_ptr result, const bi_ptr i, const int n);

/* <result> := <i> >> <n> */
INLINE_DECL bi_ptr bi_shift_right( bi_ptr result, const bi_ptr i, const int n);

/* create a random of length <length> bits */
/*  res := random( length)  */
INLINE_DECL bi_ptr bi_urandom( bi_ptr result, const long length);


/* res := <n> mod <m> */
INLINE_DECL bi_ptr bi_mod_si( bi_ptr result, const bi_ptr n, const long m);

/* res := <n> mod <m> */
INLINE_DECL bi_ptr bi_mod( bi_ptr result, const bi_ptr n, const bi_ptr m);

/* result := (inverse of <i>) mod <m> */
/* if the inverse exist, return >0, otherwise 0 */
INLINE_DECL int bi_invert_mod( bi_ptr result, const bi_ptr i, const bi_ptr m);

/* generate a prime number of <length> bits  */
INLINE_DECL bi_ptr bi_generate_prime( bi_ptr result, const long bit_length);

/* generate a safe prime number of <length> bits  */
/* by safe we mean a prime p so that (p-1)/2 is also prime */
INLINE_DECL bi_ptr bi_generate_safe_prime( bi_ptr result, const long bit_length);

/* return in <result> the greatest common divisor of <a> and <b> */
/* <result> := gcd( <a>, <b>) */
INLINE_DECL bi_ptr bi_gcd( bi_ptr result, bi_ptr a, bi_ptr b);


#endif /*BI_OPENSSL_*/

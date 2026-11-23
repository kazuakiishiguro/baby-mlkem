#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <time.h>
#include <immintrin.h>
static uint64_t now(void){struct timespec t;clock_gettime(CLOCK_MONOTONIC,&t);return t.tv_sec*1000000000ull+t.tv_nsec;}
volatile long sink;
__attribute__((noinline)) int16_t empty_fn(int16_t x){return (int16_t)(x+1);}
__attribute__((noinline)) int reg_loop(int n,int seed){int a=seed,b=2,c=3;for(int i=0;i<n;i++){a=a*3+b;b=b^a;c=c+a;}return a+b+c;}
__attribute__((noinline)) int mem_loop(const int16_t*a,int n){int s=0;for(int i=0;i<n;i++)s+=a[i];return s;}
#ifdef __AVX2__
__attribute__((noinline)) int simd_loop(const int16_t*a,int n){__m256i s=_mm256_setzero_si256();for(int i=0;i<n;i+=16)s=_mm256_add_epi16(s,_mm256_loadu_si256((const __m256i*)(a+i)));int16_t o[16];_mm256_storeu_si256((__m256i*)o,s);int r=0;for(int i=0;i<16;i++)r+=o[i];return r;}
#endif
#define T(label,expr) {uint64_t t0=now();long v=0,N=200000;for(long i=0;i<N;i++)v+=(long)(expr);uint64_t t1=now();sink=v;printf("%-13s %7.1f ns/op\n",label,(double)(t1-t0)/(double)N);}
int main(void){
  static int16_t a[512];
  for(int i=0;i<512;i++)a[i]=(int16_t)(i&0x7f);
  T("empty_call", empty_fn((int16_t)(i&1)));
  T("reg_loop256", reg_loop(256,(int)(i&1)));
#ifdef __AVX2__
  T("simd_256", simd_loop(a+(i&7),256));
#endif
  T("mem_256", mem_loop(a+(i&7),256));
  return 0;
}

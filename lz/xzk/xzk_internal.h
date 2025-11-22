#ifndef XZK_INTERNAL_H
#define XZK_INTERNAL_H

// _GNU_SOURCE est géré par le CMakeLists.txt (-D_GNU_SOURCE)
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>

// --- Constantes & Configuration ---
#define XZK_MAGIC_WORD 0x304B5A58u
#define XZK_VERSION 1
#define XZK_CHUNK_SIZE (256 * 1024)
#define XZK_IO_BUFFER_SIZE (1024 * 1024)

#define XZK_FILE_HEADER_SIZE 8
#define XZK_BLOCK_HEADER_SIZE 12
#define XZK_NUM_HEADER_BINARY_SIZE 16
#define XZK_GNR_HEADER_BINARY_SIZE 16
#define XZK_SECTION_DESC_BINARY_SIZE 12

#define XZK_BLOCK_FLAG_NONE 0u
#define XZK_BLOCK_FLAG_CHECKSUM 0x80u
#define XZK_DEFAULT_CHECKSUM_ENABLED 0

typedef enum
{
    XZK_BLOCK_RAW = 0,
    XZK_BLOCK_GNR = 1,
    XZK_BLOCK_NUM = 2
} xzk_block_type_t;

typedef enum
{
    XZK_SECTION_ENCODING_RAW = 0,
    XZK_SECTION_ENCODING_RLE = 1,
    XZK_SECTION_ENCODING_BITPACK = 2,
    XZK_SECTION_ENCODING_FSE = 3,
    XZK_SECTION_ENCODING_BITPACK_FSE = 4
} xzk_section_encoding_t;

typedef struct
{
    uint8_t block_type;
    uint8_t block_flags;
    uint16_t reserved;
    uint32_t comp_size;
    uint32_t raw_size;
} xzk_block_header_t;

typedef struct
{
    uint32_t n_sequences;
    uint32_t n_literals;
    uint8_t enc_lit, enc_litlen, enc_mlen, enc_off;
} xzk_gnr_header_t;

typedef struct
{
    uint32_t comp_size;
    uint32_t raw_size;
} xzk_section_desc_t;

typedef struct
{
    uint64_t n_values;
    uint16_t frame_size;
} xzk_num_header_t;

// --- Intrinsics & Macros ---
#if defined(__x86_64__) || defined(_M_X64) || defined(__i386__) || defined(_M_IX86)
#include <immintrin.h>
#if defined(__AVX2__)
#define XZK_USE_AVX2
#endif
#if defined(__SSE4_1__) || defined(__AVX__)
#define XZK_USE_SSE41
#endif
#elif defined(__aarch64__) || defined(_M_ARM64)
#include <arm_neon.h>
#define XZK_USE_NEON
#endif

#if defined(__GNUC__) || defined(__clang__)
#define LIKELY(x) (__builtin_expect(!!(x), 1))
#define UNLIKELY(x) (__builtin_expect(!!(x), 0))
#define XZK_PREFETCH_READ(ptr) __builtin_prefetch((const void *)(ptr), 0, 3)
#define XZK_PREFETCH_WRITE(ptr) __builtin_prefetch((const void *)(ptr), 1, 3)
#else
#define LIKELY(x) (x)
#define UNLIKELY(x) (x)
#define XZK_PREFETCH_READ(ptr)
#define XZK_PREFETCH_WRITE(ptr)
#endif

// Support MSVC BitScan
#ifdef _MSC_VER
#include <intrin.h>
#pragma intrinsic(_BitScanReverse)
#endif

// --- Helpers Mémoire (Endianness) ---
static inline uint16_t xzk_le16(const void *p)
{
    uint16_t v;
    memcpy(&v, p, sizeof(v));
    return v;
}
static inline uint32_t xzk_le32(const void *p)
{
    uint32_t v;
    memcpy(&v, p, sizeof(v));
    return v;
}
static inline uint64_t xzk_le64(const void *p)
{
    uint64_t v;
    memcpy(&v, p, sizeof(v));
    return v;
}
static inline void xzk_store_le16(void *p, uint16_t v) { memcpy(p, &v, sizeof(v)); }
static inline void xzk_store_le32(void *p, uint32_t v) { memcpy(p, &v, sizeof(v)); }
static inline void xzk_store_le64(void *p, uint64_t v) { memcpy(p, &v, sizeof(v)); }

static inline uint8_t xzk_highbit32(uint32_t n)
{
#ifdef _MSC_VER
    unsigned long index;
    return (n == 0) ? 0 : (_BitScanReverse(&index, n) ? (uint8_t)(index + 1) : 0);
#else
    return (n == 0) ? 0 : (32 - __builtin_clz(n));
#endif
}

static inline uint32_t xzk_zigzag_encode(int32_t n) { return ((uint32_t)n << 1) ^ (uint32_t)(n >> 31); }
static inline int32_t xzk_zigzag_decode(uint32_t n) { return (int32_t)(n >> 1) ^ -(int32_t)(n & 1); }

static inline int xzk_is_rle(const uint8_t *src, size_t len)
{
    if (len < 8)
        return 0;
    uint8_t first = src[0];
    for (size_t i = 1; i < len; i++)
        if (src[i] != first)
            return 0;
    return 1;
}

// --- Contextes de Compression (LZ) ---
#define XZK_LZ_HASH_BITS 15
#define XZK_LZ_HASH_SIZE (1 << XZK_LZ_HASH_BITS)
#define XZK_LZ_WINDOW_SIZE (1 << 16)
#define XZK_LZ_MIN_MATCH 4
#define XZK_LZ_MAX_DIST (XZK_LZ_WINDOW_SIZE - 1)

typedef struct
{
    uint32_t lit_len, match_len, offset;
} xzk_seq_t;

typedef struct
{
    uint32_t *hash_table;
    xzk_seq_t *sequences;
    uint32_t *buf_ll, *buf_ml, *buf_off;
    uint8_t *literals;
    size_t max_seq_count;
} xzk_cctx_t;

// --- Fonctions Partagées (Common) ---
int xzk_cctx_init(xzk_cctx_t *ctx, size_t chunk_size);
void xzk_cctx_free(xzk_cctx_t *ctx);

uint32_t xzk_xxh32(const void *restrict input, size_t len, uint32_t seed);
uint32_t xzk_copy_and_checksum(const uint8_t *src, uint8_t *dst, size_t len, uint32_t seed);

int xzk_read_file_header(const uint8_t *src, size_t src_size);
int xzk_write_file_header(uint8_t *dst, size_t dst_capacity);
int xzk_read_block_header(const uint8_t *src, size_t src_size, xzk_block_header_t *bh);
int xzk_write_block_header(uint8_t *dst, size_t dst_capacity, const xzk_block_header_t *bh);

// Helpers Bits & Headers spécifiques
typedef struct
{
    const uint8_t *ptr;
    const uint8_t *end;
    uint64_t accum;
    int bits;
} xzk_bit_reader_t;
void xzk_br_init(xzk_bit_reader_t *br, const uint8_t *src, size_t size);
uint32_t xzk_br_get(xzk_bit_reader_t *br, uint8_t n);

int xzk_bitpack_stream_32(const uint32_t *restrict src, size_t count, uint8_t *restrict dst, size_t dst_cap, uint8_t bits);
int xzk_write_num_header(uint8_t *dst, size_t rem, const xzk_num_header_t *nh);
int xzk_read_num_header(const uint8_t *src, size_t src_size, xzk_num_header_t *nh);
int xzk_write_gnr_header_and_desc(uint8_t *dst, size_t rem, const xzk_gnr_header_t *gh, const xzk_section_desc_t desc[4]);
int xzk_read_gnr_header_and_desc(const uint8_t *src, size_t len, xzk_gnr_header_t *gh, xzk_section_desc_t desc[4]);

// --- Moteur de Streaming Générique ---
typedef int (*xzk_chunk_processor_t)(xzk_cctx_t *ctx, const uint8_t *in, size_t in_sz, uint8_t *out, size_t out_cap);

int xzk_stream_engine_run(FILE *f_in, FILE *f_out, int n_threads, int mode, xzk_chunk_processor_t func);

int compress_chunk_wrapper(xzk_cctx_t *ctx, const uint8_t *chunk, size_t sz, uint8_t *dst, size_t cap);

int decompress_chunk_wrapper(xzk_cctx_t *ctx, const uint8_t *src, size_t src_sz, uint8_t *dst, size_t dst_cap);

#endif // XZK_INTERNAL_H
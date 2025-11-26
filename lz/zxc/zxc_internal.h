/*
 * Copyright (c) 2025, Bertrand Lebonnois
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef ZXC_INTERNAL_H
#define ZXC_INTERNAL_H

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef __cplusplus
extern "C"
{
#endif

#if defined(__GNUC__) || defined(__clang__)
#define RESTRICT __restrict__
#elif defined(_MSC_VER)
#define RESTRICT __restrict
#else
#define RESTRICT
#endif

    /*
     * ============================================================================
     * CONSTANTS & FILE FORMAT
     * ============================================================================
     */

#define ZXC_MAGIC_WORD 0x0043585Au       // Magic signature "ZXC0" (Little Endian)
#define ZXC_VERSION 1                    // Current file format version
#define ZXC_CHUNK_SIZE (256 * 1024)      // Size of data blocks processed by threads
#define ZXC_IO_BUFFER_SIZE (1024 * 1024) // Size of stdio buffers

// Binary Header Sizes
#define ZXC_FILE_HEADER_SIZE 8 // Magic (4 bytes) + Version (1 byte) + Reserved (3 bytes)
#define ZXC_BLOCK_HEADER_SIZE \
    12                                // Type (1) + Flags (1) + Reserved (2) + Comp Size (4) + Raw Size (4)
#define ZXC_NUM_HEADER_BINARY_SIZE 16 // Num Header: N Values (8) + Frame Size (2) + Reserved (6)
#define ZXC_GNR_HEADER_BINARY_SIZE \
    16 // GNR Header: N Sequences (4) + N Literals (4) + 4 x 1-byte Encoding Types
#define ZXC_SECTION_DESC_BINARY_SIZE \
    12 // Section Desc: Comp Size (4) + Raw Size (4) + Reserved (4)

// Block Flags
#define ZXC_BLOCK_FLAG_NONE 0u         // No flags
#define ZXC_BLOCK_FLAG_CHECKSUM 0x80u  // Block has a checksum (4 bytes after header)
#define ZXC_DEFAULT_CHECKSUM_ENABLED 0 // By default, checksums are disabled

    /**
     * @enum zxc_block_type_t
     * @brief Defines the different types of data blocks supported by the ZXC format.
     *
     * This enumeration categorizes blocks based on the compression strategy applied:
     * - `ZXC_BLOCK_RAW`: Used for high-entropy data that cannot be compressed effectively.
     * - `ZXC_BLOCK_GNR`: General-purpose compression using LZ77-based variants.
     * - `ZXC_BLOCK_NUM`: Specialized compression for numeric data using Delta encoding and Bitpacking.
     */
    typedef enum
    {
        ZXC_BLOCK_RAW = 0,
        ZXC_BLOCK_GNR = 1,
        ZXC_BLOCK_NUM = 2
    } zxc_block_type_t;

    /**
     * @enum zxc_section_encoding_t
     * @brief Specifies the encoding methods used for internal data sections.
     *
     * These modes determine how specific components (like literals, match lengths, or offsets)
     * are stored within a block.
     * - `ZXC_SECTION_ENCODING_RAW`: Data is stored uncompressed.
     * - `ZXC_SECTION_ENCODING_RLE`: Run-Length Encoding.
     * - `ZXC_SECTION_ENCODING_BITPACK`: Bitpacking for integer values.
     * - `ZXC_SECTION_ENCODING_FSE`: Finite State Entropy (Reserved).
     * - `ZXC_SECTION_ENCODING_BITPACK_FSE`: Combined Bitpacking and FSE (Reserved).
     */
    typedef enum
    {
        ZXC_SECTION_ENCODING_RAW = 0,
        ZXC_SECTION_ENCODING_RLE = 1,
        ZXC_SECTION_ENCODING_BITPACK = 2,
        ZXC_SECTION_ENCODING_FSE = 3,        // Reserved for Entropy Coding
        ZXC_SECTION_ENCODING_BITPACK_FSE = 4 // Reserved
    } zxc_section_encoding_t;

    /**
     * @struct zxc_block_header_t
     * @brief Represents the on-disk header structure for a ZXC block.
     *
     * This structure contains metadata required to parse and decompress a block.
     *
     * @var zxc_block_header_t::block_type
     * The type of the block (see zxc_block_type_t).
     * @var zxc_block_header_t::block_flags
     * Bit flags indicating properties like checksum presence.
     * @var zxc_block_header_t::reserved
     * Reserved bytes for future protocol extensions.
     * @var zxc_block_header_t::comp_size
     * The size of the compressed data payload in bytes (excluding this header).
     * @var zxc_block_header_t::raw_size
     * The size of the data after decompression.
     */
    typedef struct
    {
        uint8_t block_type;  // Block type (e.g., RAW, GNR, NUM)
        uint8_t block_flags; // Flags (e.g., checksum presence)
        uint16_t reserved;   // Reserved for future use
        uint32_t comp_size;  // Compressed size excluding header
        uint32_t raw_size;   // Decompressed size
    } zxc_block_header_t;

    /**
     * @struct zxc_gnr_header_t
     * @brief Header specific to General (LZ-based) compression blocks.
     *
     * This header follows the main block header when the block type is GNR. It describes
     * the layout of sequences and literals.
     *
     * @var zxc_gnr_header_t::n_sequences
     * The total count of LZ sequences in the block.
     * @var zxc_gnr_header_t::n_literals
     * The total count of literal bytes.
     * @var zxc_gnr_header_t::enc_lit
     * Encoding method used for the literal stream.
     * @var zxc_gnr_header_t::enc_litlen
     * Encoding method used for the literal lengths stream.
     * @var zxc_gnr_header_t::enc_mlen
     * Encoding method used for the match lengths stream.
     * @var zxc_gnr_header_t::enc_off
     * Encoding method used for the offset stream.
     */
    typedef struct
    {
        uint32_t n_sequences;                           // Number of sequences
        uint32_t n_literals;                            // Number of literals
        uint8_t enc_lit, enc_litlen, enc_mlen, enc_off; // Encoding methods per stream
    } zxc_gnr_header_t;

    /**
     * @struct zxc_section_desc_t
     * @brief Describes the size attributes of a specific data section.
     *
     * Used to track the compressed and uncompressed sizes of sub-components
     * (e.g., a literal stream or offset stream) within a block.
     *
     * @var zxc_section_desc_t::comp_size
     * The size of the section on disk (compressed).
     * @var zxc_section_desc_t::raw_size
     * The size of the section in memory (decompressed).
     */
    typedef struct
    {
        uint32_t comp_size;
        uint32_t raw_size;
    } zxc_section_desc_t;

    /**
     * @struct zxc_num_header_t
     * @brief Header specific to Numeric compression blocks.
     *
     * This header follows the main block header when the block type is NUM.
     *
     * @var zxc_num_header_t::n_values
     * The total number of numeric values encoded in the block.
     * @var zxc_num_header_t::frame_size
     * The size of the frame used for processing.
     */
    typedef struct
    {
        uint64_t n_values;
        uint16_t frame_size;
    } zxc_num_header_t;

/*
 * ============================================================================
 * SIMD INTRINSICS & COMPILER MACROS
 * ============================================================================
 */
#if defined(__x86_64__) || defined(_M_X64) || defined(__i386__) || defined(_M_IX86)
#include <immintrin.h>
#if defined(__AVX512F__) && defined(__AVX512BW__)
#define XZK_USE_AVX512
#endif
#if defined(__AVX2__)
#define ZXC_USE_AVX2
#endif
#if defined(__SSE4_1__) || defined(__AVX__)
#define ZXC_USE_SSE41
#endif
#elif defined(__aarch64__) || defined(_M_ARM64)
#include <arm_neon.h>
#define ZXC_USE_NEON
#endif

#if defined(__GNUC__) || defined(__clang__)
#define LIKELY(x) (__builtin_expect(!!(x), 1))
#define UNLIKELY(x) (__builtin_expect(!!(x), 0))
#define ZXC_PREFETCH_READ(ptr) __builtin_prefetch((const void *)(ptr), 0, 3)
#define ZXC_PREFETCH_WRITE(ptr) __builtin_prefetch((const void *)(ptr), 1, 3)
#else
#define LIKELY(x) (x)
#define UNLIKELY(x) (x)
#define ZXC_PREFETCH_READ(ptr)
#define ZXC_PREFETCH_WRITE(ptr)
#endif

#ifdef _MSC_VER
#include <intrin.h>
#pragma intrinsic(_BitScanReverse)
#endif

    /*
     * ============================================================================
     * MEMORY & ENDIANNESS HELPERS
     * ============================================================================
     * Functions to handle unaligned memory access and Little Endian conversion.
     */
    static inline uint16_t zxc_le16(const void *p)
    {
        uint16_t v;
        memcpy(&v, p, sizeof(v));
        return v;
    }
    static inline uint32_t zxc_le32(const void *p)
    {
        uint32_t v;
        memcpy(&v, p, sizeof(v));
        return v;
    }
    static inline uint64_t zxc_le64(const void *p)
    {
        uint64_t v;
        memcpy(&v, p, sizeof(v));
        return v;
    }
    static inline void zxc_store_le16(void *p, uint16_t v) { memcpy(p, &v, sizeof(v)); }
    static inline void zxc_store_le32(void *p, uint32_t v) { memcpy(p, &v, sizeof(v)); }
    static inline void zxc_store_le64(void *p, uint64_t v) { memcpy(p, &v, sizeof(v)); }

    /*
     * Returns the index of the highest set bit (Log2 approximation).
     */
    static inline uint8_t zxc_highbit32(uint32_t n)
    {
#ifdef _MSC_VER
        unsigned long index;
        return (n == 0) ? 0 : (_BitScanReverse(&index, n) ? (uint8_t)(index + 1) : 0);
#else
    return (n == 0) ? 0 : (32 - __builtin_clz(n));
#endif
    }

    /*
     * ZigZag encoding maps signed integers to unsigned integers so that numbers with
     * small absolute values (positive or negative) become small unsigned integers.
     */
    static inline uint32_t zxc_zigzag_encode(int32_t n)
    {
        return ((uint32_t)n << 1) ^ (uint32_t)(n >> 31);
    }
    static inline int32_t zxc_zigzag_decode(uint32_t n)
    {
        return (int32_t)(n >> 1) ^ -(int32_t)(n & 1);
    }

    // Checks if a buffer consists of a single repeated byte (Run-Length Encoding candidate).
    static inline int zxc_is_rle(const uint8_t *src, size_t len)
    {
        if (len < 8)
            return 0;
        uint8_t first = src[0];
        for (size_t i = 1; i < len; i++)
            if (src[i] != first)
                return 0;
        return 1;
    }

/*
 * ============================================================================
 * COMPRESSION CONTEXT & STRUCTS
 * ============================================================================
 */
#define ZXC_LZ_HASH_BITS 15                      // 32K entries
#define ZXC_LZ_HASH_SIZE (1 << ZXC_LZ_HASH_BITS) // Hash table size
#define ZXC_LZ_WINDOW_SIZE (1 << 16)             // 64KB sliding window
#define ZXC_LZ_MIN_MATCH 4                       // Minimum match length
#define ZXC_LZ_MAX_DIST (ZXC_LZ_WINDOW_SIZE - 1) // Maximum offset distance

    // Represents a found LZ77 sequence (Literal Length, Match Length, Offset)
    /**
     * @typedef zxc_seq_t
     * @brief Represents a sequence in the ZXC compression algorithm.
     *
     * This structure holds the components of a match or literal sequence used
     * during the compression or decompression process.
     *
     * @field lit_len   The length of the literal run preceding the match.
     * @field match_len The length of the match found.
     * @field offset    The backward distance (offset) to the start of the match.
     */
    typedef struct
    {
        uint32_t lit_len, match_len, offset;
    } zxc_seq_t;

    /**
     * @typedef zxc_cctx_t
     * @brief Compression Context structure.
     *
     * This structure holds the state and buffers required for the compression process.
     * It is designed to be reused across multiple blocks or calls to avoid the
     * overhead of repeated memory allocations.
     *
     * @field hash_table Pointer to the hash table used for LZ77 match finding. Stores indices into the
     * input buffer based on hash values. field chain_table Pointer to the chain table for collision
     * resolution. Used to store previous positions for hash collisions (if chaining is enabled).
     * @field sequences Pointer to the buffer holding intermediate sequences. Holds the raw
     * match/literal length data before entropy encoding.
     *  @field buf_ll Pointer to the buffer for literal length codes.
     * @field buf_ml Pointer to the buffer for match length codes.
     * @field buf_off Pointer to the buffer for offset codes.
     * @field literals Pointer to the buffer for raw literal bytes. These are the bytes that could not
     * be matched during LZ77.
     * @field max_seq_count The capacity of the sequences buffer. Allows reusing the hash table without
     * zeroing it out completely between blocks.
     *  @field epoch Current epoch counter for lazy hash table invalidation. Allows reusing the hash
     * table without zeroing it out completely between blocks.
     * @field checksum_enabled Flag indicating if checksums should be computed. 0 = disabled, 1 =
     * enabled.
     * @field compression_level The configured compression level. Determines trade-offs between speed
     * and compression ratio (e.g., hash table size, search depth).
     */
    typedef struct
    {
        uint32_t *hash_table;  // Hash table for LZ77
        uint32_t *chain_table; // Chain table for collision resolution
        zxc_seq_t *sequences;  // Buffer for sequences
        uint32_t *buf_ll;      // Buffer for literal lengths
        uint32_t *buf_ml;      // Buffer for match lengths
        uint32_t *buf_off;     // Buffer for offsets
        uint8_t *literals;     // Buffer for literal bytes
        size_t max_seq_count;  // Maximum number of sequences
        uint32_t epoch;        // Current epoch for hash table
        int checksum_enabled;  // Checksum enabled flag
        int compression_level; // Compression level
    } zxc_cctx_t;

    /**
     * @typedef zxc_bit_reader_t
     * @brief Internal bit reader structure for ZXC compression/decompression.
     *
     * This structure maintains the state of the bit stream reading operation.
     * It buffers bits from the input byte stream into an accumulator to allow
     * reading variable-length bit sequences.
     *
     * @field ptr Pointer to the current position in the input byte stream. This pointer advances as
     * bytes are loaded into the accumulator.
     * @field end Pointer to the end of the input byte stream. Used to prevent reading past the bounds
     * of the input buffer.
     * @field accum Bit accumulator holding buffered bits. A 64-bit buffer that holds the bits currently
     * loaded from the stream but not yet consumed.
     * @field bits Number of valid bits currently in the accumulator. Indicates how many bits are
     * available in @c accum to be read.
     */
    typedef struct
    {
        const uint8_t *ptr;
        const uint8_t *end;
        uint64_t accum;
        int bits;
    } zxc_bit_reader_t;

    /**
     * @typedef zxc_chunk_processor_t
     * @brief Function pointer type for processing a chunk of data.
     *
     * This type defines the signature for internal functions responsible for processing
     * (compressing or transforming) a specific chunk of input data.
     *
     * @param ctx     Pointer to the compression context containing state and configuration.
     * @param in      Pointer to the input data buffer.
     * @param in_sz   Size of the input data in bytes.
     * @param out     Pointer to the output buffer where processed data will be written.
     * @param out_cap Capacity of the output buffer in bytes.
     *
     * @return The number of bytes written to the output buffer on success, or a negative
     *         error code on failure.
     */
    typedef int (*zxc_chunk_processor_t)(zxc_cctx_t *ctx, const uint8_t *in, size_t in_sz, uint8_t *out,
                                         size_t out_cap);

    /*
     * INTERNAL API
     * ------------
     */
    /**
     * @brief Initializes a ZXC compression context.
     *
     * Sets up the internal state required for compression operations, allocating
     * necessary buffers based on the chunk size and compression level.
     *
     * @param ctx Pointer to the compression context structure to initialize.
     * @param chunk_size The size of the data chunks to process.
     * @param mode The compression mode (e.g., fast, high compression).
     * @param level The specific compression level (1-9).
     * @return 0 on success, or a negative error code on failure.
     */
    int zxc_cctx_init(zxc_cctx_t *ctx, size_t chunk_size, int mode, int level);

    /**
     * @brief Frees resources associated with a ZXC compression context.
     *
     * Releases memory allocated during initialization and resets the context state.
     *
     * @param ctx Pointer to the compression context to free.
     */
    void zxc_cctx_free(zxc_cctx_t *ctx);

    /**
     * @brief Calculates a 32-bit XXH3checksum for a given input buffer.
     *
     * @param input Pointer to the data buffer.
     * @param len Length of the data in bytes.
     * @param seed Initial seed value for the hash calculation.
     * @return The calculated 32-bit hash value.
     */
    uint32_t zxc_checksum(const void *RESTRICT input, size_t len, uint32_t seed);

    /**
     * @brief Copies memory and calculates a checksum in a single pass.
     *
     * This function optimizes performance by combining the memory copy operation
     * with the checksum calculation, avoiding a second pass over the data.
     *
     * @param src Pointer to the source buffer.
     * @param dst Pointer to the destination buffer.
     * @param len Number of bytes to copy and checksum.
     * @param seed Initial seed value for the hash calculation.
     * @return The calculated 32-bit hash value of the source data.
     */
    uint32_t zxc_copy_and_checksum(const uint8_t *src, uint8_t *dst, size_t len, uint32_t seed);

    /**
     * @brief Validates and reads the ZXC file header from a source buffer.
     *
     * Checks for the correct magic bytes and version number.
     *
     * @param src Pointer to the start of the file data.
     * @param src_size Size of the available source data (must be at least header size).
     * @return The size of the header in bytes on success, or a negative error code.
     */
    int zxc_read_file_header(const uint8_t *src, size_t src_size);

    /**
     * @brief Writes the standard ZXC file header to a destination buffer.
     *
     * Writes the magic bytes and version information.
     *
     * @param dst Pointer to the destination buffer.
     * @param dst_capacity Maximum capacity of the destination buffer.
     * @return The number of bytes written on success, or a negative error code.
     */
    int zxc_write_file_header(uint8_t *dst, size_t dst_capacity);

    /**
     * @brief Parses a block header from the source stream.
     *
     * Decodes the block size, compression type, and checksum flags into the
     * provided block header structure.
     *
     * @param src Pointer to the current position in the source stream.
     * @param src_size Available bytes remaining in the source stream.
     * @param bh Pointer to a block header structure to populate.
     * @return The number of bytes read (header size) on success, or a negative error code.
     */
    int zxc_read_block_header(const uint8_t *src, size_t src_size, zxc_block_header_t *bh);

    /**
     * @brief Encodes a block header into the destination buffer.
     *
     * Serializes the information contained in the block header structure (size,
     * flags, etc.) into the binary format expected by the decoder.
     *
     * @param dst Pointer to the destination buffer.
     * @param dst_capacity Maximum capacity of the destination buffer.
     * @param bh Pointer to the block header structure containing the metadata.
     * @return The number of bytes written on success, or a negative error code.
     */
    int zxc_write_block_header(uint8_t *dst, size_t dst_capacity, const zxc_block_header_t *bh);

    /**
     * @brief Initializes a bit reader structure.
     *
     * Sets up the internal state of the bit reader to read from the specified source buffer.
     *
     * @param br Pointer to the bit reader structure to initialize.
     * @param src Pointer to the source buffer containing the data to read.
     * @param size The size of the source buffer in bytes.
     */
    void zxc_br_init(zxc_bit_reader_t *br, const uint8_t *src, size_t size);

    /**
     * @brief Reads a specified number of bits from the bit reader.
     *
     * @param br Pointer to the initialized bit reader structure.
     * @param n The number of bits to read (must be <= 32).
     * @return The value read from the stream as a 32-bit unsigned integer.
     */
    uint32_t zxc_br_get(zxc_bit_reader_t *br, uint8_t n);

    /**
     * @brief Bit-packs a stream of 32-bit integers into a destination buffer.
     *
     * Compresses an array of 32-bit integers by packing them using a specified number of bits per
     * integer.
     *
     * @param src Pointer to the source array of 32-bit integers.
     * @param count The number of integers to pack.
     * @param dst Pointer to the destination buffer where packed data will be written.
     * @param dst_cap The capacity of the destination buffer in bytes.
     * @param bits The number of bits to use for each integer during packing.
     * @return The number of bytes written to the destination buffer, or a negative error code on
     * failure.
     */
    int zxc_bitpack_stream_32(const uint32_t *RESTRICT src, size_t count, uint8_t *RESTRICT dst,
                              size_t dst_cap, uint8_t bits);

    /**
     * @brief Writes a numeric header structure to a destination buffer.
     *
     * Serializes the `zxc_num_header_t` structure into the output stream.
     *
     * @param dst Pointer to the destination buffer.
     * @param rem The remaining space in the destination buffer.
     * @param nh Pointer to the numeric header structure to write.
     * @return The number of bytes written, or a negative error code if the buffer is too small.
     */
    int zxc_write_num_header(uint8_t *dst, size_t rem, const zxc_num_header_t *nh);

    /**
     * @brief Reads a numeric header structure from a source buffer.
     *
     * Deserializes data from the input stream into a `zxc_num_header_t` structure.
     *
     * @param src Pointer to the source buffer.
     * @param src_size The size of the source buffer available for reading.
     * @param nh Pointer to the numeric header structure to populate.
     * @return The number of bytes read from the source, or a negative error code on failure.
     */
    int zxc_read_num_header(const uint8_t *src, size_t src_size, zxc_num_header_t *nh);

    /**
     * @brief Writes a generic header and section descriptors to a destination buffer.
     *
     * Serializes the `zxc_gnr_header_t` and an array of 4 section descriptors.
     *
     * @param dst Pointer to the destination buffer.
     * @param rem The remaining space in the destination buffer.
     * @param gh Pointer to the generic header structure to write.
     * @param desc Array of 4 section descriptors to write.
     * @return The number of bytes written, or a negative error code if the buffer is too small.
     */
    int zxc_write_gnr_header_and_desc(uint8_t *dst, size_t rem, const zxc_gnr_header_t *gh,
                                      const zxc_section_desc_t desc[4]);

    /**
     * @brief Reads a generic header and section descriptors from a source buffer.
     *
     * Deserializes data into a `zxc_gnr_header_t` and an array of 4 section descriptors.
     *
     * @param src Pointer to the source buffer.
     * @param len The length of the source buffer available for reading.
     * @param gh Pointer to the generic header structure to populate.
     * @param desc Array of 4 section descriptors to populate.
     * @return The number of bytes read from the source, or a negative error code on failure.
     */
    int zxc_read_gnr_header_and_desc(const uint8_t *src, size_t len, zxc_gnr_header_t *gh,
                                     zxc_section_desc_t desc[4]);

    /**
     * @brief Runs the main compression/decompression stream engine.
     *
     * This function orchestrates the processing of data from an input stream to an output stream,
     * potentially utilizing multiple threads for parallel processing. It handles the setup,
     * execution, and teardown of the streaming process based on the specified configuration.
     *
     * @param f_in Pointer to the input file stream (source data).
     * @param f_out Pointer to the output file stream (destination data).
     * @param n_threads The number of threads to use for processing. If 0 or 1, processing may be
     * sequential.
     * @param mode The operation mode (e.g., compression or decompression).
     * @param level The compression level to apply (relevant only for compression mode).
     * @param checksum Flag indicating whether to calculate and verify checksums (1 for yes, 0 for no).
     * @param func The chunk processing callback function (`zxc_chunk_processor_t`) responsible for
     *             handling individual data blocks.
     *
     * @return Returns 0 on success, or a non-zero error code on failure.
     */
    int zxc_stream_engine_run(FILE *f_in, FILE *f_out, int n_threads, int mode, int level, int checksum,
                              zxc_chunk_processor_t func);

    int zxc_decompress_chunk_wrapper(zxc_cctx_t *ctx, const uint8_t *src, size_t src_sz,
                                     uint8_t *dst, size_t dst_cap);

    int zxc_compress_chunk_wrapper(zxc_cctx_t *ctx, const uint8_t *chunk, size_t sz,
                                   uint8_t *dst, size_t cap);

#ifdef __cplusplus
}
#endif

#endif // ZXC_INTERNAL_H
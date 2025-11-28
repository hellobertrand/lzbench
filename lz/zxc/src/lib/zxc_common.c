/*
 * Copyright (c) 2025, Bertrand Lebonnois
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include "../../include/zxc.h"
#include "zxc_internal.h"

/*
 * ============================================================================
 * WINDOWS THREADING EMULATION
 * ============================================================================
 * Maps POSIX pthread calls to Windows Native API (CriticalSection,
 * ConditionVariable, Threads). Allows the same threading logic to compile on
 * Linux/macOS and Windows.
 */
#ifdef _WIN32
#include <process.h>
#include <sys/types.h>
#include <windows.h>

// Simple sysconf emulation to get core count
static int zxc_get_num_procs(void) {
    SYSTEM_INFO sysinfo;
    GetSystemInfo(&sysinfo);
    return sysinfo.dwNumberOfProcessors;
}

typedef CRITICAL_SECTION pthread_mutex_t;
typedef CONDITION_VARIABLE pthread_cond_t;
typedef HANDLE pthread_t;

#define pthread_mutex_init(m, a) InitializeCriticalSection(m)
#define pthread_mutex_destroy(m) DeleteCriticalSection(m)
#define pthread_mutex_lock(m) EnterCriticalSection(m)
#define pthread_mutex_unlock(m) LeaveCriticalSection(m)

#define pthread_cond_init(c, a) InitializeConditionVariable(c)
#define pthread_cond_destroy(c) (void)(0)
#define pthread_cond_wait(c, m) SleepConditionVariableCS(c, m, INFINITE)
#define pthread_cond_signal(c) WakeConditionVariable(c)
#define pthread_cond_broadcast(c) WakeAllConditionVariable(c)

typedef struct {
    void* (*func)(void*);
    void* arg;
} zxc_win_thread_arg_t;

static unsigned __stdcall zxc_win_thread_entry(void* p) {
    zxc_win_thread_arg_t* a = (zxc_win_thread_arg_t*)p;
    void* (*f)(void*) = a->func;
    void* arg = a->arg;
    free(a);
    f(arg);
    return 0;
}

static int pthread_create(pthread_t* thread, const void* attr, void* (*start_routine)(void*),
                          void* arg) {
    zxc_win_thread_arg_t* wrapper = malloc(sizeof(zxc_win_thread_arg_t));
    if (!wrapper) return -1;
    wrapper->func = start_routine;
    wrapper->arg = arg;
    uintptr_t handle = _beginthreadex(NULL, 0, zxc_win_thread_entry, wrapper, 0, NULL);
    if (handle == 0) {
        free(wrapper);
        return -1;
    }
    *thread = (HANDLE)handle;
    return 0;
}

static int pthread_join(pthread_t thread, void** retval) {
    WaitForSingleObject(thread, INFINITE);
    CloseHandle(thread);
    return 0;
}

#define sysconf(x) zxc_get_num_procs()
#define _SC_NPROCESSORS_ONLN 0

#else
#include <pthread.h>
#include <unistd.h>
#endif

/*
 * ============================================================================
 * CONTEXT MANAGEMENT
 * ============================================================================
 */

/**
 * @brief Initializes the ZXC compression context.
 *
 * This function allocates memory for internal buffers and structures required
 * for compression based on the provided chunk size and compression level. It
 * sets up hash tables, chain tables, sequence buffers, and literal buffers.
 *
 * @param ctx Pointer to the ZXC compression context structure to initialize.
 * @param chunk_size The size of the data chunk to be compressed. This
 * determines the allocation size for various internal buffers.
 * @param mode The operation mode. If 0, the context is zeroed but no memory is
 *             allocated (useful for simple initialization). If non-zero, full
 *             allocation occurs.
 * @param level The desired compression level to be stored in the context.
 *
 * @return 0 on success, or -1 if memory allocation fails for any of the
 * internal buffers.
 */
int zxc_cctx_init(zxc_cctx_t* ctx, size_t chunk_size, int mode, int level) {
    memset(ctx, 0, sizeof(zxc_cctx_t));
    ctx->checksum_enabled = ZXC_DEFAULT_CHECKSUM_ENABLED;

    if (mode == 0) return 0;

    size_t max_seq = chunk_size / 4 + 256;
    ctx->hash_table = malloc(2 * ZXC_LZ_HASH_SIZE * sizeof(uint32_t));
    ctx->chain_table = malloc(chunk_size * sizeof(uint32_t));
    ctx->sequences = malloc(max_seq * sizeof(zxc_seq_t));
    ctx->buf_ll = malloc(max_seq * sizeof(uint32_t));
    ctx->buf_ml = malloc(max_seq * sizeof(uint32_t));
    ctx->buf_off = malloc(max_seq * sizeof(uint32_t));
    ctx->literals = malloc(chunk_size);
    ctx->max_seq_count = max_seq;
    ctx->epoch = 1;
    ctx->compression_level = level;

    if (!ctx->hash_table || !ctx->chain_table || !ctx->sequences || !ctx->buf_ll || !ctx->buf_ml ||
        !ctx->buf_off || !ctx->literals)
        return -1;

    memset(ctx->hash_table, 0, 2 * ZXC_LZ_HASH_SIZE * sizeof(uint32_t));
    return 0;
}

/**
 * @brief Frees the memory allocated for a compression context.
 *
 * This function releases all internal buffers and tables associated with the
 * given ZXC compression context structure. It does not free the context pointer
 * itself, only its members.
 *
 * @param ctx Pointer to the compression context to clean up.
 */
void zxc_cctx_free(zxc_cctx_t* ctx) {
    free(ctx->hash_table);
    free(ctx->chain_table);
    free(ctx->sequences);
    free(ctx->buf_ll);
    free(ctx->buf_ml);
    free(ctx->buf_off);
    free(ctx->literals);
}

/*
 * ============================================================================
 * CHECKSUM IMPLEMENTATION (XXH3)
 * ============================================================================
 * Uses XXH3 (64-bit) truncated to 32-bit for extreme performance (> 30GB/s).
 */

#define XXH_INLINE_ALL
#include "../../include/xxhash.h"

uint32_t zxc_checksum(const void* data, size_t len, uint32_t seed) {
    return (uint32_t)XXH3_64bits_withSeed(data, len, (uint64_t)seed);
}

uint32_t zxc_copy_and_checksum(const uint8_t* src, uint8_t* dst, size_t len, uint32_t seed) {
    memcpy(dst, src, len);
    return (uint32_t)XXH3_64bits_withSeed(dst, len, (uint64_t)seed);
}

/*
 * ============================================================================
 * HEADER I/O
 * ============================================================================
 * Serialization and deserialization of file and block headers.
 */

/**
 * @brief Writes the ZXC file header to the destination buffer.
 *
 * This function stores the magic word (little-endian) and the version number
 * into the provided buffer. It ensures the buffer has sufficient capacity
 * before writing.
 *
 * @param dst The destination buffer where the header will be written.
 * @param dst_capacity The total capacity of the destination buffer in bytes.
 * @return The number of bytes written (ZXC_FILE_HEADER_SIZE) on success,
 *         or -1 if the destination capacity is insufficient.
 */
int zxc_write_file_header(uint8_t* dst, size_t dst_capacity) {
    if (UNLIKELY(dst_capacity < ZXC_FILE_HEADER_SIZE)) return -1;
    zxc_store_le32(dst, ZXC_MAGIC_WORD);
    dst[4] = ZXC_VERSION;
    dst[5] = 0;
    dst[6] = 0;
    dst[7] = 0;
    return ZXC_FILE_HEADER_SIZE;
}

/**
 * @brief Reads and validates the ZXC file header from a source buffer.
 *
 * This function checks if the provided source buffer is large enough to contain
 * a ZXC file header and verifies that the magic word and version number match
 * the expected ZXC format specifications.
 *
 * @param src Pointer to the source buffer containing the file data.
 * @param src_size Size of the source buffer in bytes.
 * @return 0 if the header is valid, -1 otherwise (e.g., buffer too small,
 * invalid magic word, or incorrect version).
 */
int zxc_read_file_header(const uint8_t* src, size_t src_size) {
    if (UNLIKELY(src_size < ZXC_FILE_HEADER_SIZE)) return -1;
    if (UNLIKELY(zxc_le32(src) != ZXC_MAGIC_WORD || src[4] != ZXC_VERSION)) return -1;
    return 0;
}

/**
 * @brief Writes a ZXC block header to a destination buffer.
 *
 * This function serializes the contents of a `zxc_block_header_t` structure
 * into a byte array in little-endian format. It ensures the destination buffer
 * has sufficient capacity before writing.
 *
 * @param dst Pointer to the destination buffer where the header will be
 * written.
 * @param dst_capacity The total size of the destination buffer in bytes.
 * @param bh Pointer to the source block header structure containing the data to
 * write.
 *
 * @return The number of bytes written (ZXC_BLOCK_HEADER_SIZE) on success,
 *         or -1 if the destination buffer capacity is insufficient.
 */
int zxc_write_block_header(uint8_t* dst, size_t dst_capacity, const zxc_block_header_t* bh) {
    if (UNLIKELY(dst_capacity < ZXC_BLOCK_HEADER_SIZE)) return -1;
    dst[0] = bh->block_type;
    dst[1] = bh->block_flags;
    zxc_store_le16(dst + 2, bh->reserved);
    zxc_store_le32(dst + 4, bh->comp_size);
    zxc_store_le32(dst + 8, bh->raw_size);
    return ZXC_BLOCK_HEADER_SIZE;
}

/**
 * @brief Read and parses a ZXC block header from a source buffer.
 *
 * This function extracts the block type, flags, reserved fields, compressed
 * size, and raw size from the first `ZXC_BLOCK_HEADER_SIZE` bytes of the source
 * buffer. It handles endianness conversion for multi-byte fields (Little
 * Endian).
 *
 * @param src       Pointer to the source buffer containing the block data.
 * @param src_size  The size of the source buffer in bytes.
 * @param bh        Pointer to a `zxc_block_header_t` structure where the parsed
 *                  header information will be stored.
 *
 * @return 0 on success, or -1 if the source buffer is smaller than the
 *         required block header size.
 */
int zxc_read_block_header(const uint8_t* src, size_t src_size, zxc_block_header_t* bh) {
    if (UNLIKELY(src_size < ZXC_BLOCK_HEADER_SIZE)) return -1;
    bh->block_type = src[0];
    bh->block_flags = src[1];
    bh->reserved = zxc_le16(src + 2);
    bh->comp_size = zxc_le32(src + 4);
    bh->raw_size = zxc_le32(src + 8);
    return 0;
}

/*
 * ============================================================================
 * BITPACKING UTILITIES
 * ============================================================================
 */

/**
 * @brief Initializes the bit reader structure.
 *
 * This function sets up the bit reader state to read from the specified source
 * buffer. It initializes the internal pointers and loads the initial bits into
 * the accumulator. If the source buffer is large enough (>= 8 bytes), it
 * preloads a full 64-bit word using little-endian ordering. Otherwise, it loads
 * the available bytes one by one.
 *
 * @param br Pointer to the bit reader structure to initialize.
 * @param src Pointer to the source buffer containing the data to read.
 * @param size The size of the source buffer in bytes.
 */
void zxc_br_init(zxc_bit_reader_t* br, const uint8_t* src, size_t size) {
    br->ptr = src;
    br->end = src + size;
    br->accum = 0;
    br->bits = 0;

    br->accum = zxc_le64(br->ptr);
    br->ptr += 8;
    br->bits = 64;
}

/**
 * @brief Reads a specified number of bits from the bit reader.
 *
 * This function extracts `n` bits from the internal accumulator of the bit
 * reader. If the accumulator does not contain enough bits, it refills the
 * accumulator from the input buffer. It handles both fast-path refilling (when
 * at least 8 bytes are available) and a byte-by-byte slow path for the end of
 * the buffer.
 *
 * @param br Pointer to the bit reader context structure.
 * @param n The number of bits to read (must be <= 32).
 * @return The extracted value as a 32-bit unsigned integer.
 */
uint32_t zxc_br_get(zxc_bit_reader_t* br, uint8_t n) {
    if (UNLIKELY(br->bits < n)) {
        int bytes = (64 - br->bits) >> 3;
        uint64_t v = zxc_le64(br->ptr);
        br->accum |= (v << br->bits);
        br->ptr += bytes;
        br->bits += bytes * 8;
    }

    uint32_t val = (uint32_t)(br->accum & ((1UL << n) - 1));
    br->accum >>= n;
    br->bits -= n;
    return val;
}

// Packs an array of 32-bit integers into a bitstream using 'bits' bits per
// integer.
/**
 * @brief Packs an array of 32-bit integers into a byte stream using a specified
 * bit width.
 *
 * This function compresses a sequence of 32-bit integers by storing only the
 * specified number of least significant bits for each integer. The resulting
 * bits are concatenated contiguously into the destination buffer.
 *
 * @param src      Pointer to the source array of 32-bit integers.
 * @param count    The number of integers to pack.
 * @param dst      Pointer to the destination byte buffer where packed data will
 * be written. The buffer is zero-initialized before writing.
 * @param dst_cap  The capacity of the destination buffer in bytes.
 * @param bits     The number of bits to use for each integer (bit width).
 *                 Must be between 1 and 32.
 *
 * @return The number of bytes written to the destination buffer on success,
 *         or -1 if the destination capacity is insufficient.
 */
int zxc_bitpack_stream_32(const uint32_t* restrict src, size_t count, uint8_t* restrict dst,
                          size_t dst_cap, uint8_t bits) {
    size_t out_bytes = ((count * bits) + 7) / 8;

    if (UNLIKELY(dst_cap < out_bytes)) return -1;

    size_t bit_pos = 0;
    memset(dst, 0, out_bytes);

    for (size_t i = 0; i < count; i++) {
        uint64_t v = (uint64_t)src[i] << (bit_pos % 8);
        size_t byte_idx = bit_pos / 8;
        dst[byte_idx] |= (uint8_t)v;
        if (bits + (bit_pos % 8) > 8) dst[byte_idx + 1] |= (uint8_t)(v >> 8);
        if (bits + (bit_pos % 8) > 16) dst[byte_idx + 2] |= (uint8_t)(v >> 16);
        if (bits + (bit_pos % 8) > 24) dst[byte_idx + 3] |= (uint8_t)(v >> 24);
        if (bits + (bit_pos % 8) > 32) dst[byte_idx + 4] |= (uint8_t)(v >> 32);
        bit_pos += bits;
    }
    return (int)out_bytes;
}

/**
 * @brief Writes the numeric header structure to a binary buffer.
 *
 * This function serializes the contents of a `zxc_num_header_t` structure into
 * the provided destination buffer in little-endian format. It ensures that the
 * buffer has sufficient remaining space before writing.
 *
 * The binary layout written is as follows:
 * - Offset 0: Number of values (64-bit, Little Endian)
 * - Offset 8: Frame size (16-bit, Little Endian)
 * - Offset 10: Reserved/Padding (16-bit, set to 0)
 * - Offset 12: Reserved/Padding (32-bit, set to 0)
 *
 * @param dst Pointer to the destination buffer where the header will be
 * written.
 * @param rem The remaining size available in the destination buffer.
 * @param nh Pointer to the source numeric header structure containing the
 * values to write.
 *
 * @return The number of bytes written (ZXC_NUM_HEADER_BINARY_SIZE) on success,
 *         or -1 if the remaining buffer size is insufficient.
 */
int zxc_write_num_header(uint8_t* dst, size_t rem, const zxc_num_header_t* nh) {
    if (UNLIKELY(rem < ZXC_NUM_HEADER_BINARY_SIZE)) return -1;

    zxc_store_le64(dst, nh->n_values);
    zxc_store_le16(dst + 8, nh->frame_size);
    zxc_store_le16(dst + 10, 0);
    zxc_store_le32(dst + 12, 0);
    return ZXC_NUM_HEADER_BINARY_SIZE;
}

/**
 * @brief Reads the numerical header from a binary source.
 *
 * This function parses the header information from the provided source buffer
 * and populates the given `zxc_num_header_t` structure. It expects the source
 * to contain at least `ZXC_NUM_HEADER_BINARY_SIZE` bytes.
 *
 * The header structure in the binary format is expected to be:
 * - 8 bytes: Number of values (Little Endian 64-bit integer)
 * - 2 bytes: Frame size (Little Endian 16-bit integer)
 *
 * @param src Pointer to the source buffer containing the binary header data.
 * @param src_size The size of the source buffer in bytes.
 * @param nh Pointer to the `zxc_num_header_t` structure to be populated.
 *
 * @return 0 on success, or -1 if the source buffer is smaller than the required
 * header size.
 */
int zxc_read_num_header(const uint8_t* src, size_t src_size, zxc_num_header_t* nh) {
    if (UNLIKELY(src_size < ZXC_NUM_HEADER_BINARY_SIZE)) return -1;

    nh->n_values = zxc_le64(src);
    nh->frame_size = zxc_le16(src + 8);
    return 0;
}

/**
 * @brief Writes the general header and section descriptors to a destination
 * buffer.
 *
 * This function serializes the provided general header structure
 * (`zxc_gnr_header_t`) and an array of four section descriptors
 * (`zxc_section_desc_t`) into a binary format at the specified destination
 * memory location.
 *
 * The binary layout written is as follows:
 * - **General Header (16 bytes):**
 *   - 4 bytes: Number of sequences (Little Endian)
 *   - 4 bytes: Number of literals (Little Endian)
 *   - 1 byte:  Literal encoding type
 *   - 1 byte:  Literal length encoding type
 *   - 1 byte:  Match length encoding type
 *   - 1 byte:  Offset encoding type
 *   - 4 bytes: Reserved/Padding (set to 0)
 * - **Section Descriptors (4 entries * 12 bytes each):**
 *   - 4 bytes: Compressed size (Little Endian)
 *   - 4 bytes: Raw size (Little Endian)
 *   - 4 bytes: Reserved/Padding (set to 0)
 *
 * @param dst   Pointer to the destination buffer where data will be written.
 * @param rem   Remaining size in bytes available in the destination buffer.
 * @param gh    Pointer to the source general header structure.
 * @param desc  Array of 4 section descriptors to be written.
 *
 * @return The total number of bytes written on success, or -1 if the remaining
 *         buffer space (`rem`) is insufficient.
 */
int zxc_write_gnr_header_and_desc(uint8_t* dst, size_t rem, const zxc_gnr_header_t* gh,
                                  const zxc_section_desc_t desc[4]) {
    size_t needed = ZXC_GNR_HEADER_BINARY_SIZE + 4 * ZXC_SECTION_DESC_BINARY_SIZE;

    if (UNLIKELY(rem < needed)) return -1;

    zxc_store_le32(dst, gh->n_sequences);
    zxc_store_le32(dst + 4, gh->n_literals);

    dst[8] = gh->enc_lit;
    dst[9] = gh->enc_litlen;
    dst[10] = gh->enc_mlen;
    dst[11] = gh->enc_off;

    zxc_store_le32(dst + 12, 0);
    uint8_t* p = dst + ZXC_GNR_HEADER_BINARY_SIZE;

    for (int i = 0; i < 4; i++) {
        zxc_store_le32(p, desc[i].comp_size);
        zxc_store_le32(p + 4, desc[i].raw_size);
        zxc_store_le32(p + 8, 0);
        p += 12;
    }
    return (int)needed;
}

/**
 * Reads the general header and section descriptors from a binary source buffer.
 *
 * This function parses the initial bytes of a ZXC compressed stream to populate
 * the general header structure and an array of four section descriptors. It
 * verifies that the source buffer is large enough to contain the required
 * binary data before reading.
 *
 * @param src   Pointer to the source buffer containing the binary data.
 * @param len   Length of the source buffer in bytes.
 * @param gh    Pointer to the `zxc_gnr_header_t` structure to be populated.
 * @param desc  Array of 4 `zxc_section_desc_t` structures to be populated with
 * section details.
 *
 * @return 0 on success, or -1 if the source buffer length is insufficient.
 */
int zxc_read_gnr_header_and_desc(const uint8_t* src, size_t len, zxc_gnr_header_t* gh,
                                 zxc_section_desc_t desc[4]) {
    size_t needed = ZXC_GNR_HEADER_BINARY_SIZE + 4 * ZXC_SECTION_DESC_BINARY_SIZE;

    if (UNLIKELY(len < needed)) return -1;

    gh->n_sequences = zxc_le32(src);
    gh->n_literals = zxc_le32(src + 4);
    gh->enc_lit = src[8];
    gh->enc_litlen = src[9];
    gh->enc_mlen = src[10];
    gh->enc_off = src[11];

    const uint8_t* p = src + ZXC_GNR_HEADER_BINARY_SIZE;

    for (int i = 0; i < 4; i++) {
        desc[i].comp_size = zxc_le32(p);
        desc[i].raw_size = zxc_le32(p + 4);
        p += 12;
    }
    return 0;
}

/**
 * @brief Calculates the maximum possible size of the compressed output.
 *
 * This function estimates the worst-case scenario for the compressed size based
 * on the input size. It accounts for the file header, block headers, and
 * potential overhead for each chunk, ensuring the destination buffer is large
 * enough to hold the result even if the data is incompressible.
 *
 * @param input_size The size of the uncompressed input data in bytes.
 * @return The maximum potential size of the compressed data in bytes.
 */
size_t zxc_max_compressed_size(size_t input_size) {
    size_t n = (input_size + ZXC_CHUNK_SIZE - 1) / ZXC_CHUNK_SIZE;
    if (n == 0) n = 1;
    return ZXC_FILE_HEADER_SIZE + (n * (ZXC_BLOCK_HEADER_SIZE + 4 + 64)) + input_size;
}

/*
 * ============================================================================
 * STREAMING ENGINE (Producer / Worker / Consumer)
 * ============================================================================
 * Implements a Ring Buffer architecture to parallelize block processing.
 */

/**
 * @enum job_status_t
 * @brief Represents the lifecycle states of a processing job within the ring
 * buffer.
 *
 * @var JOB_STATUS_FREE
 *      The job slot is empty and available to be filled with new data by the
 * writer.
 * @var JOB_STATUS_FILLED
 *      The job slot has been populated with input data and is ready for
 * processing by a worker.
 * @var JOB_STATUS_PROCESSED
 *      The worker has finished processing the data; the result is ready to be
 * consumed/written out.
 */
typedef enum { JOB_STATUS_FREE, JOB_STATUS_FILLED, JOB_STATUS_PROCESSED } job_status_t;

/**
 * @struct zxc_stream_job_t
 * @brief Represents a single unit of work (a chunk of data) to be processed.
 *
 * This structure holds the input and output buffers for a specific chunk of
 * data, along with its processing status. It is padded to align with cache
 * lines to prevent false sharing in a multi-threaded environment.
 *
 * @var zxc_stream_job_t::in_buf
 *      Pointer to the buffer containing raw input data.
 * @var zxc_stream_job_t::in_cap
 *      The total allocated capacity of the input buffer.
 * @var zxc_stream_job_t::in_sz
 *      The actual size of the valid data currently in the input buffer.
 * @var zxc_stream_job_t::out_buf
 *      Pointer to the buffer where processed (compressed/decompressed) data is
 * stored.
 * @var zxc_stream_job_t::out_cap
 *      The total allocated capacity of the output buffer.
 * @var zxc_stream_job_t::result_sz
 *      The actual size of the valid data produced in the output buffer.
 * @var zxc_stream_job_t::job_id
 *      A unique identifier for the job, often used for ordering or debugging.
 * @var zxc_stream_job_t::status
 *      The current state of this job (Free, Filled, or Processed).
 * @var zxc_stream_job_t::pad
 *      Padding bytes to ensure the structure size aligns with typical cache
 * lines (64 bytes), minimizing cache contention between threads accessing
 * adjacent jobs.
 */
typedef struct {
    uint8_t* in_buf;
    size_t in_cap, in_sz;
    uint8_t* out_buf;
    size_t out_cap, result_sz;
    int job_id;
    job_status_t status;
    char pad[64];  // Prevent False Sharing
} zxc_stream_job_t;

/**
 * @struct zxc_stream_ctx_t
 * @brief The main context structure managing the streaming
 * compression/decompression state.
 *
 * This structure orchestrates the producer-consumer workflow. It manages the
 * ring buffer of jobs, the worker queue, synchronization primitives (mutexes
 * and condition variables), and configuration settings for the compression
 * algorithm.
 *
 * @var zxc_stream_ctx_t::jobs
 *      Array of job structures acting as the ring buffer.
 * @var zxc_stream_ctx_t::ring_size
 *      The total number of slots in the jobs array.
 * @var zxc_stream_ctx_t::worker_queue
 *      A circular queue containing indices of jobs ready to be picked up by
 * worker threads.
 * @var zxc_stream_ctx_t::wq_head
 *      Index of the head of the worker queue (where workers take jobs).
 * @var zxc_stream_ctx_t::wq_tail
 *      Index of the tail of the worker queue (where the writer adds jobs).
 * @var zxc_stream_ctx_t::wq_count
 *      Current number of items in the worker queue.
 * @var zxc_stream_ctx_t::lock
 *      Mutex used to protect access to shared resources (queue indices, status
 * changes).
 * @var zxc_stream_ctx_t::cond_reader
 *      Condition variable to signal the output thread (reader) that processed
 * data is available.
 * @var zxc_stream_ctx_t::cond_worker
 *      Condition variable to signal worker threads that new work is available.
 * @var zxc_stream_ctx_t::cond_writer
 *      Condition variable to signal the input thread (writer) that job slots
 * are free.
 * @var zxc_stream_ctx_t::shutdown_workers
 *      Flag indicating that worker threads should terminate.
 * @var zxc_stream_ctx_t::compression_mode
 *      Indicates the operation mode (e.g., compression or decompression).
 * @var zxc_stream_ctx_t::io_error
 *      Volatile flag to signal if an I/O error occurred during processing.
 * @var zxc_stream_ctx_t::processor
 *      Function pointer or object responsible for the actual chunk processing
 * logic.
 * @var zxc_stream_ctx_t::write_idx
 *      The index of the next job slot to be written to by the main thread.
 * @var zxc_stream_ctx_t::checksum_enabled
 *      Flag indicating whether checksum verification/generation is active.
 * @var zxc_stream_ctx_t::compression_level
 *      The configured level of compression (trading off speed vs. ratio).
 */
typedef struct {
    zxc_stream_job_t* jobs;
    int ring_size;
    int* worker_queue;
    int wq_head, wq_tail, wq_count;
    pthread_mutex_t lock;
    pthread_cond_t cond_reader, cond_worker, cond_writer;
    int shutdown_workers;
    int compression_mode;
    volatile int io_error;
    zxc_chunk_processor_t processor;
    int write_idx;
    int checksum_enabled;
    int compression_level;
} zxc_stream_ctx_t;

/**
 * @struct writer_args_t
 * @brief Structure containing arguments for the writer callback function.
 *
 * This structure is used to pass necessary context and state information
 * to the function responsible for writing compressed or decompressed data
 * to a file stream.
 *
 * @var writer_args_t::ctx
 * Pointer to the ZXC stream context, holding the state of the
 * compression/decompression stream.
 *
 * @var writer_args_t::f
 * Pointer to the output file stream where data will be written.
 *
 * @var writer_args_t::total_bytes
 * Accumulator for the total number of bytes written to the file so far.
 */
typedef struct {
    zxc_stream_ctx_t* ctx;
    FILE* f;
    int total_bytes;
} writer_args_t;

/**
 * @brief Worker thread function for parallel stream processing.
 *
 * This function serves as the entry point for worker threads in the ZXC
 * streaming compression/decompression context. It continuously retrieves jobs
 * from a shared work queue, processes them using a thread-local compression
 * context (`zxc_cctx_t`), and signals the writer thread upon completion.
 *
 * The worker lifecycle involves:
 * 1. Initializing a local compression context based on the shared stream
 * context settings.
 * 2. Entering a loop to wait for available jobs or a shutdown signal.
 * 3. Dequeuing a job ID from the ring buffer in a thread-safe manner.
 * 4. Executing the processing function (compression or decompression) on the
 * job's data.
 * 5. Updating the job status to `JOB_STATUS_PROCESSED`.
 * 6. Signaling the writer thread if the processed job is the next one expected
 * for output.
 * 7. Cleaning up resources upon receiving a shutdown signal.
 *
 * @param arg A pointer to the shared stream context (`zxc_stream_ctx_t`).
 * @return Always returns NULL.
 */
static void* zxc_stream_worker(void* arg) {
    zxc_stream_ctx_t* ctx = (zxc_stream_ctx_t*)arg;
    zxc_cctx_t cctx;

    if (zxc_cctx_init(&cctx, ZXC_CHUNK_SIZE, ctx->compression_mode, ctx->compression_level) != 0)
        return NULL;

    cctx.checksum_enabled = ctx->checksum_enabled;
    cctx.compression_level = ctx->compression_level;

    while (1) {
        zxc_stream_job_t* job = NULL;
        pthread_mutex_lock(&ctx->lock);
        while (ctx->wq_count == 0 && !ctx->shutdown_workers) {
            pthread_cond_wait(&ctx->cond_worker, &ctx->lock);
        }
        if (ctx->shutdown_workers && ctx->wq_count == 0) {
            pthread_mutex_unlock(&ctx->lock);
            break;
        }
        int jid = ctx->worker_queue[ctx->wq_tail];
        ctx->wq_tail = (ctx->wq_tail + 1) % ctx->ring_size;
        ctx->wq_count--;
        job = &ctx->jobs[jid];
        pthread_mutex_unlock(&ctx->lock);

        job->result_sz = ctx->processor(&cctx, job->in_buf, job->in_sz, job->out_buf, job->out_cap);

        pthread_mutex_lock(&ctx->lock);
        job->status = JOB_STATUS_PROCESSED;
        if (jid == ctx->write_idx) pthread_cond_broadcast(&ctx->cond_writer);
        pthread_mutex_unlock(&ctx->lock);
    }
    zxc_cctx_free(&cctx);
    return NULL;
}

/**
 * @brief Asynchronous writer thread function.
 *
 * This function runs as a separate thread responsible for writing processed
 * data chunks to the output file. It operates on a ring buffer of jobs shared
 * with the reader and worker threads.
 *
 * The workflow is as follows:
 * 1. Waits for a job at the current write index to reach the
 * `JOB_STATUS_PROCESSED` state.
 * 2. Checks for a termination signal (result size of -1).
 * 3. Writes the processed data buffer to the output file stream if valid.
 * 4. Updates the total bytes written.
 * 5. Marks the job as `JOB_STATUS_FREE` and signals the reader thread that a
 * slot is available.
 * 6. Advances the write index in the ring buffer.
 *
 * @param arg Pointer to a `writer_args_t` structure containing the stream
 * context, the output file handle, and a counter for total bytes written.
 * @return Always returns NULL.
 */
static void* zxc_async_writer(void* arg) {
    writer_args_t* args = (writer_args_t*)arg;
    zxc_stream_ctx_t* ctx = args->ctx;
    while (1) {
        zxc_stream_job_t* job = &ctx->jobs[ctx->write_idx];
        pthread_mutex_lock(&ctx->lock);
        while (job->status != JOB_STATUS_PROCESSED)
            pthread_cond_wait(&ctx->cond_writer, &ctx->lock);

        if (job->result_sz == (size_t)-1) {
            pthread_mutex_unlock(&ctx->lock);
            break;
        }
        pthread_mutex_unlock(&ctx->lock);

        if (args->f && job->result_sz > 0) {
            if (fwrite(job->out_buf, 1, job->result_sz, args->f) != job->result_sz) {
                ctx->io_error = 1;
            }
        }
        args->total_bytes += job->result_sz;

        pthread_mutex_lock(&ctx->lock);
        job->status = JOB_STATUS_FREE;
        ctx->write_idx = (ctx->write_idx + 1) % ctx->ring_size;
        pthread_cond_signal(&ctx->cond_reader);
        pthread_mutex_unlock(&ctx->lock);
    }
    return NULL;
}

/**
 * @brief Orchestrates the multithreaded streaming compression or decompression
 * engine.
 *
 * This function initializes the stream context, allocates the necessary ring
 * buffer memory for jobs and I/O buffers, and spawns the worker threads and the
 * asynchronous writer thread. It acts as the main "producer" (reader) loop,
 * reading data from the input file, preparing job structures, and dispatching
 * them to the worker queue.
 *
 * The function handles the synchronization between the reader, the workers, and
 * the writer to ensure thread-safe processing of data chunks. It also manages
 * the file headers and block headers depending on the operation mode.
 *
 * @param f_in      Pointer to the input file stream (source).
 * @param f_out     Pointer to the output file stream (destination).
 * @param n_threads Number of worker threads to spawn. If set to 0 or less, the
 * function automatically detects the number of online processors.
 * @param mode      Operation mode: 1 for compression, 0 for decompression.
 * @param level     Compression level to be applied (relevant for compression
 * mode).
 * @param checksum  Flag indicating whether to enable checksum
 * generation/verification.
 * @param func      Function pointer to the chunk processor (compression or
 * decompression logic).
 *
 * @return The total number of bytes written to the output stream on success, or
 * -1 if an initialization or I/O error occurred.
 */
int zxc_stream_engine_run(FILE* f_in, FILE* f_out, int n_threads, int mode, int level, int checksum,
                          zxc_chunk_processor_t func) {
    if (!f_in) return -1;

    zxc_stream_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.compression_mode = mode;
    ctx.processor = func;
    ctx.io_error = 0;
    ctx.checksum_enabled = checksum;
    ctx.compression_level = level;
    int num_threads = (n_threads > 0) ? n_threads : (int)sysconf(_SC_NPROCESSORS_ONLN);
    ctx.ring_size = num_threads * 4;

    size_t max_out = zxc_max_compressed_size(ZXC_CHUNK_SIZE);
    size_t alloc_in = ((mode) ? ZXC_CHUNK_SIZE : max_out) + ZXC_PAD_SIZE;
    size_t alloc_out = ((mode) ? max_out : ZXC_CHUNK_SIZE) + ZXC_PAD_SIZE;

    uint8_t* mem_block =
        malloc(ctx.ring_size * (sizeof(zxc_stream_job_t) + sizeof(int) + alloc_in + alloc_out));
    if (!mem_block) return -1;
    uint8_t* ptr = mem_block;
    ctx.jobs = (zxc_stream_job_t*)ptr;
    ptr += ctx.ring_size * sizeof(zxc_stream_job_t);
    ctx.worker_queue = (int*)ptr;
    ptr += ctx.ring_size * sizeof(int);
    uint8_t* buf_in = ptr;
    ptr += ctx.ring_size * alloc_in;
    uint8_t* buf_out = ptr;

    for (int i = 0; i < ctx.ring_size; i++) {
        ctx.jobs[i].job_id = i;
        ctx.jobs[i].status = JOB_STATUS_FREE;
        ctx.jobs[i].in_buf = buf_in + (i * alloc_in);
        ctx.jobs[i].in_cap = alloc_in - ZXC_PAD_SIZE;
        ctx.jobs[i].out_buf = buf_out + (i * alloc_out);
        ctx.jobs[i].out_cap = alloc_out - ZXC_PAD_SIZE;
        ctx.jobs[i].result_sz = 0;
    }

    pthread_mutex_init(&ctx.lock, NULL);
    pthread_cond_init(&ctx.cond_reader, NULL);
    pthread_cond_init(&ctx.cond_worker, NULL);
    pthread_cond_init(&ctx.cond_writer, NULL);

    pthread_t* workers = malloc(num_threads * sizeof(pthread_t));
    for (int i = 0; i < num_threads; i++)
        pthread_create(&workers[i], NULL, zxc_stream_worker, &ctx);

    writer_args_t w_args = {&ctx, f_out, 0};
    if (mode == 1 && f_out) {
        uint8_t h[8];
        zxc_write_file_header(h, 8);
        if (fwrite(h, 1, 8, f_out) != 8) {
            ctx.io_error = 1;
        }
        w_args.total_bytes = 8;
    }
    pthread_t writer_th;
    pthread_create(&writer_th, NULL, zxc_async_writer, &w_args);

    int read_idx = 0;
    int read_eof = 0;

    if (mode == 0 && f_in) {
        uint8_t h[8];
        if (fread(h, 1, 8, f_in) != 8 || zxc_read_file_header(h, 8) != 0) read_eof = 1;
    }

    // Reader Loop: Reads from file, prepares jobs, pushes to worker queue.
    while (!read_eof && f_in && !ctx.io_error) {
        zxc_stream_job_t* job = &ctx.jobs[read_idx];
        pthread_mutex_lock(&ctx.lock);
        while (job->status != JOB_STATUS_FREE) pthread_cond_wait(&ctx.cond_reader, &ctx.lock);
        pthread_mutex_unlock(&ctx.lock);

        if (ctx.io_error) break;

        size_t read_sz = 0;
        if (mode == 1) {
            read_sz = fread(job->in_buf, 1, ZXC_CHUNK_SIZE, f_in);
            if (read_sz == 0) read_eof = 1;
        } else {
            uint8_t bh_buf[ZXC_BLOCK_HEADER_SIZE + 4];
            size_t h_read = fread(bh_buf, 1, ZXC_BLOCK_HEADER_SIZE, f_in);
            if (h_read < ZXC_BLOCK_HEADER_SIZE) {
                read_eof = 1;
            } else {
                zxc_block_header_t bh;
                zxc_read_block_header(bh_buf, ZXC_BLOCK_HEADER_SIZE, &bh);
                int has_crc = (bh.block_flags & ZXC_BLOCK_FLAG_CHECKSUM);

                if (has_crc) {
                    if (fread(bh_buf + ZXC_BLOCK_HEADER_SIZE, 1, 4, f_in) != 4) {
                        read_eof = 1;
                    }
                }

                memcpy(job->in_buf, bh_buf, ZXC_BLOCK_HEADER_SIZE + (has_crc ? 4 : 0));
                size_t body_read = fread(job->in_buf + ZXC_BLOCK_HEADER_SIZE + (has_crc ? 4 : 0), 1,
                                         bh.comp_size, f_in);
                read_sz = ZXC_BLOCK_HEADER_SIZE + (has_crc ? 4 : 0) + body_read;
                if (body_read != bh.comp_size) read_eof = 1;
            }
        }
        if (read_eof && read_sz == 0) break;

        job->in_sz = read_sz;
        pthread_mutex_lock(&ctx.lock);
        job->status = JOB_STATUS_FILLED;
        ctx.worker_queue[ctx.wq_head] = read_idx;
        ctx.wq_head = (ctx.wq_head + 1) % ctx.ring_size;
        ctx.wq_count++;
        read_idx = (read_idx + 1) % ctx.ring_size;
        pthread_cond_signal(&ctx.cond_worker);
        pthread_mutex_unlock(&ctx.lock);

        if (read_sz < ZXC_CHUNK_SIZE && mode == 1) read_eof = 1;
    }

    zxc_stream_job_t* end_job = &ctx.jobs[read_idx];
    pthread_mutex_lock(&ctx.lock);
    while (end_job->status != JOB_STATUS_FREE) pthread_cond_wait(&ctx.cond_reader, &ctx.lock);
    end_job->result_sz = -1;
    end_job->status = JOB_STATUS_PROCESSED;
    pthread_cond_broadcast(&ctx.cond_writer);
    pthread_mutex_unlock(&ctx.lock);

    pthread_join(writer_th, NULL);
    pthread_mutex_lock(&ctx.lock);
    ctx.shutdown_workers = 1;
    pthread_cond_broadcast(&ctx.cond_worker);
    pthread_mutex_unlock(&ctx.lock);
    for (int i = 0; i < num_threads; i++) pthread_join(workers[i], NULL);

    free(workers);
    free(mem_block);

    if (ctx.io_error) return -1;

    return w_args.total_bytes;
}
/*
 * Copyright (c) 2025, Bertrand Lebonnois
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
 
#ifndef ZXC_H
#define ZXC_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * ============================================================================
 * ZXC Compression Library - Public API
 * ============================================================================
 */

/*
 * STREAMING API
 * ----------------------------------------------------------------------------
 * The library uses an asynchronous pipeline architecture (Producer-Consumer)
 * via a Ring Buffer to separate I/O operations from CPU-intensive compression tasks.
 */

/**
 * @brief Compression levels available for zxc_stream_compress.
 *
 * Higher levels provide better compression ratios but require more CPU time.
 * Lower levels are faster but may result in larger output files.
 */
typedef enum { ZXC_LEVEL_FAST = 1, ZXC_LEVEL_DEFAULT = 5, ZXC_LEVEL_BEST = 9 } zxc_level_t;

/**
 * @brief Compresses data from an input stream to an output stream.
 *
 * This function sets up a multi-threaded pipeline:
 * 1. Reader Thread: Reads chunks from f_in.
 * 2. Worker Threads: Compress chunks in parallel (LZ77 + Bitpacking).
 * 3. Writer Thread: Orders the processed chunks and writes them to f_out.
 *
 * @param f_in      Input file stream (must be opened in "rb" mode).
 * @param f_out     Output file stream (must be opened in "wb" mode).
 * @param n_threads Number of worker threads to spawn (0 = auto-detect number of CPU cores).
 * @param level     Compression level (ZXC_LEVEL_FAST=1, ZXC_LEVEL_DEFAULT=5, ZXC_LEVEL_BEST=9).
 * @param checksum  If non-zero, enables checksum verification for data integrity.
 * @return          Total compressed bytes written, or -1 if an error occurred.
 */
int zxc_stream_compress(FILE* f_in, FILE* f_out, int n_threads, zxc_level_t level, int checksum);

/**
 * @brief Decompresses data from an input stream to an output stream.
 *
 * Uses the same pipeline architecture as compression to maximize throughput.
 *
 * @param f_in      Input file stream (must be opened in "rb" mode).
 * @param f_out     Output file stream (must be opened in "wb" mode).
 * @param n_threads Number of worker threads to spawn (0 = auto-detect number of CPU cores).
 * @param checksum  If non-zero, enables checksum verification for data integrity.
 * @return          Total decompressed bytes written, or -1 if an error occurred.
 */
int zxc_stream_decompress(FILE* f_in, FILE* f_out, int n_threads, int checksum);

/*
 * UTILITIES
 * ----------------------------------------------------------------------------
 */

/**
 * @brief Calculates the maximum theoretical compressed size for a given input.
 *
 * Useful for allocating output buffers before compression.
 * Accounts for file headers, block headers, and potential expansion
 * of incompressible data.
 *
 * @param input_size Size of the input data in bytes.
 * @return           Maximum required buffer size in bytes.
 */
size_t zxc_max_compressed_size(size_t input_size);

#ifdef __cplusplus
}
#endif

#endif  // ZXC_H
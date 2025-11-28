/*
 * Copyright (c) 2025, Bertrand Lebonnois
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include "../../include/zxc.h"
#include "zxc_internal.h"

// Force inlining for critical paths
#if defined(__GNUC__) || defined(__clang__)
#define ZXC_ALWAYS_INLINE inline __attribute__((always_inline))
#elif defined(_MSC_VER)
#define ZXC_ALWAYS_INLINE __forceinline
#else
#define ZXC_ALWAYS_INLINE inline
#endif

/*
 * Bitstream consumption helper.
 * Uses 1ULL to ensure 64-bit precision during shifting.
 */
static ZXC_ALWAYS_INLINE uint32_t zxc_br_consume_fast(zxc_bit_reader_t *br,
                                                      uint8_t n) {
#if defined(__BMI2__) && defined(__x86_64__)
  uint32_t val = (uint32_t)_bzhi_u64(br->accum, n);
#else
  uint32_t val = (uint32_t)(br->accum & ((1ULL << n) - 1));
#endif
  br->accum >>= n;
  br->bits -= n;
  return val;
}

/*
 * Ensures that the bitstream accumulator has enough bits.
 * If not, it pulls 64 bits from the source buffer.
 */
static ZXC_ALWAYS_INLINE void zxc_br_ensure(zxc_bit_reader_t *br, int needed) {
  if (UNLIKELY(br->bits < needed)) {
    int safe_bits = (br->bits < 0) ? 0 : br->bits;
    br->bits = safe_bits;

// Mask out garbage bits
#if defined(__BMI2__) && defined(__x86_64__)
    br->accum = _bzhi_u64(br->accum, safe_bits);
#else
    br->accum &= ((1ULL << safe_bits) - 1);
#endif

    const uint8_t *p_loc = br->ptr;

    uint64_t raw = zxc_le64(p_loc);
    int consumed = (64 - safe_bits) >> 3;
    br->accum |= (raw << safe_bits);
    p_loc += consumed;
    br->bits = safe_bits + consumed * 8;

    br->ptr = p_loc;
  }
}

/**
 * @brief Decodes a block of numerical data compressed with the ZXC format.
 *
 * This function reads a compressed numerical block from the source buffer,
 * parses the header to determine the number of values and encoding parameters,
 * and then decompresses the data into the destination buffer. It handles
 * delta-encoding and zigzag decoding to reconstruct the original 32-bit
 * integers.
 *
 * The decoding process involves:
 * 1. Reading the block header (`zxc_num_header_t`).
 * 2. Iterating through sub-blocks (chunks) of data.
 * 3. For each chunk, initializing a bit reader and decoding values using
 *    zigzag decoding on top of a running delta sum.
 * 4. Storing the reconstructed 32-bit values in Little Endian format.
 *
 * @param src Pointer to the source buffer containing compressed data.
 * @param src_size Size of the source buffer in bytes.
 * @param dst Pointer to the destination buffer where decompressed data will be
 * written.
 * @param dst_capacity Maximum capacity of the destination buffer in bytes.
 * @param expected_raw_size Expected size of the uncompressed data (unused in
 * current implementation).
 *
 * @return The number of bytes written to the destination buffer on success,
 *         or -1 if an error occurs (e.g., buffer overflow, invalid header,
 *         or malformed compressed stream).
 */
static int zxc_decode_block_num(const uint8_t *restrict src, size_t src_size,
                                uint8_t *restrict dst, size_t dst_capacity,
                                uint32_t expected_raw_size) {
  (void)expected_raw_size;

  zxc_num_header_t nh;
  if (UNLIKELY(zxc_read_num_header(src, src_size, &nh) != 0))
    return -1;
  const uint8_t *p = src + ZXC_NUM_HEADER_BINARY_SIZE;
  const uint8_t *p_end = src + src_size;
  uint8_t *d_ptr = dst;
  uint8_t *d_end = dst + dst_capacity;
  uint64_t vals_remaining = nh.n_values;
  uint32_t running_val = 0;

  while (vals_remaining > 0) {
    if (UNLIKELY(p + 16 > p_end))
      return -1;
    uint16_t nvals = zxc_le16(p + 0);
    uint16_t bits = zxc_le16(p + 2);
    uint32_t psize = zxc_le32(p + 12);
    p += 16;

    if (UNLIKELY(p + psize > p_end || d_ptr + nvals * 4 > d_end))
      return -1;

    zxc_bit_reader_t br;
    zxc_br_init(&br, p, psize);

    uint32_t i = 0;

    // Unrolled loop (4x) for faster decoding
    for (; i + 4 <= nvals; i += 4) {
      zxc_br_ensure(&br, bits);
      uint32_t r1 = zxc_br_consume_fast(&br, bits);
      running_val += zxc_zigzag_decode(r1);
      zxc_store_le32(d_ptr, running_val);
      d_ptr += 4;

      zxc_br_ensure(&br, bits);
      uint32_t r2 = zxc_br_consume_fast(&br, bits);
      running_val += zxc_zigzag_decode(r2);
      zxc_store_le32(d_ptr, running_val);
      d_ptr += 4;

      zxc_br_ensure(&br, bits);
      uint32_t r3 = zxc_br_consume_fast(&br, bits);
      running_val += zxc_zigzag_decode(r3);
      zxc_store_le32(d_ptr, running_val);
      d_ptr += 4;

      zxc_br_ensure(&br, bits);
      uint32_t r4 = zxc_br_consume_fast(&br, bits);
      running_val += zxc_zigzag_decode(r4);
      zxc_store_le32(d_ptr, running_val);
      d_ptr += 4;
    }

    for (; i < nvals; i++) {
      zxc_br_ensure(&br, bits);
      uint32_t r = zxc_br_consume_fast(&br, bits);
      running_val += zxc_zigzag_decode(r);
      zxc_store_le32(d_ptr, running_val);
      d_ptr += 4;
    }

    p += psize;
    vals_remaining -= nvals;
  }
  return (int)(d_ptr - dst);
}

/**
 * @brief Decompresses a "GNR" (General) encoded block of data.
 *
 * This function handles the decoding of a compressed block formatted with the
 * internal GNR structure. It reads a header and four section descriptors to
 * determine the layout of the compressed data (literals, literal lengths,
 * match lengths, and offsets).
 *
 * The decompression process involves:
 * 1. Parsing the block header and section descriptors.
 * 2. Initializing bit readers for the sequence components (LL, ML, Offset).
 * 3. Iterating through the sequences to reconstruct the data:
 *    - Copying literals (either raw or RLE encoded).
 *    - Copying matches from the history buffer (handling overlap hazards).
 * 4. Handling the final trailing literals if the generated size is less than
 * expected.
 *
 * The function employs a "Fast Path" optimization for the bulk of the data
 * where buffer boundaries are safe, using 16-byte wild copies for speed. It
 * falls back to a "Safe Path" near the end of the buffer to prevent overflows.
 *
 * @param src Pointer to the source buffer containing compressed data.
 * @param src_size Size of the source buffer in bytes.
 * @param dst Pointer to the destination buffer for decompressed data.
 * @param dst_capacity Maximum capacity of the destination buffer.
 * @param expected_raw_size The expected size of the decompressed data (used for
 * validation and trailing literals).
 *
 * @return The number of bytes written to the destination buffer on success, or
 * -1 on failure (e.g., invalid header, buffer overflow, or corrupted data).
 */
static int zxc_decode_block_gnr(const uint8_t *restrict src, size_t src_size,
                                uint8_t *restrict dst, size_t dst_capacity,
                                uint32_t expected_raw_size) {
  zxc_gnr_header_t gh;
  zxc_section_desc_t desc[4];
  if (UNLIKELY(zxc_read_gnr_header_and_desc(src, src_size, &gh, desc) != 0))
    return -1;

  const uint8_t *p_data =
      src + ZXC_GNR_HEADER_BINARY_SIZE + 4 * ZXC_SECTION_DESC_BINARY_SIZE;

  const uint8_t *ptr_lit = p_data;
  const uint8_t *ptr_tokens = ptr_lit + desc[0].comp_size;
  const uint8_t *ptr_offsets = ptr_tokens + desc[1].comp_size;
  const uint8_t *ptr_extras = ptr_offsets + desc[2].comp_size;

  if (UNLIKELY(ptr_extras + desc[3].comp_size > src + src_size))
    return -1;

  uint8_t *d_ptr = dst;
  uint8_t *d_end = dst + dst_capacity;
  uint8_t *d_end_safe = d_end - 32;
  const uint8_t *l_ptr = ptr_lit;
  const uint8_t *t_ptr = ptr_tokens;
  const uint8_t *o_ptr = ptr_offsets;
  const uint8_t *e_ptr = ptr_extras;

  uint32_t n_seq = gh.n_sequences;

  while (n_seq >= 2) {
    uint8_t token1 = *t_ptr++;
    uint32_t ll1 = token1 >> 4;
    uint32_t ml1 = token1 & 0x0F;
    uint32_t off1 = zxc_le16(o_ptr);
    o_ptr += 2;

    if (UNLIKELY(ll1 == 15)) {
      ll1 = zxc_le32(e_ptr);
      e_ptr += 4;
    }
    if (UNLIKELY(ml1 == 15)) {
      ml1 = zxc_le32(e_ptr);
      e_ptr += 4;
    }
    ml1 += ZXC_LZ_MIN_MATCH;

    uint8_t token2 = *t_ptr++;
    uint32_t ll2 = token2 >> 4;
    uint32_t ml2 = token2 & 0x0F;
    uint32_t off2 = zxc_le16(o_ptr);
    o_ptr += 2;

    if (UNLIKELY(ll2 == 15)) {
      ll2 = zxc_le32(e_ptr);
      e_ptr += 4;
    }
    if (UNLIKELY(ml2 == 15)) {
      ml2 = zxc_le32(e_ptr);
      e_ptr += 4;
    }
    ml2 += ZXC_LZ_MIN_MATCH;

    ZXC_PREFETCH_READ(l_ptr + 128);

    if (LIKELY(d_ptr + ll1 + ml1 + ll2 + ml2 < d_end_safe)) {
      // --- Sequence 1 ---
      {
        const uint8_t *src_lit = l_ptr;
        uint8_t *dst_lit = d_ptr;
        uint8_t *target_lit_end = d_ptr + ll1;
        do {
          zxc_copy16(dst_lit, src_lit);
          dst_lit += 16;
          src_lit += 16;
        } while (dst_lit < target_lit_end);
        d_ptr += ll1;
        l_ptr += ll1;

        uint8_t *match_src = d_ptr - off1;
        if (off1 >= 16) {
          uint8_t *out = d_ptr;
          uint8_t *target_match_end = d_ptr + ml1;
          do {
            zxc_copy16(out, match_src);
            out += 16;
            match_src += 16;
          } while (out < target_match_end);
          d_ptr += ml1;
        } else {
          if (off1 == 1) {
            memset(d_ptr, match_src[0], ml1);
            d_ptr += ml1;
          } else {
            for (size_t i = 0; i < ml1; i++)
              d_ptr[i] = match_src[i];
            d_ptr += ml1;
          }
        }
      }

      // --- Sequence 2 ---
      {
        const uint8_t *src_lit = l_ptr;
        uint8_t *dst_lit = d_ptr;
        uint8_t *target_lit_end = d_ptr + ll2;
        do {
          zxc_copy16(dst_lit, src_lit);
          dst_lit += 16;
          src_lit += 16;
        } while (dst_lit < target_lit_end);
        d_ptr += ll2;
        l_ptr += ll2;

        uint8_t *match_src = d_ptr - off2;
        if (off2 >= 16) {
          uint8_t *out = d_ptr;
          uint8_t *target_match_end = d_ptr + ml2;
          do {
            zxc_copy16(out, match_src);
            out += 16;
            match_src += 16;
          } while (out < target_match_end);
          d_ptr += ml2;
        } else {
          if (off2 == 1) {
            memset(d_ptr, match_src[0], ml2);
            d_ptr += ml2;
          } else {
            for (size_t i = 0; i < ml2; i++)
              d_ptr[i] = match_src[i];
            d_ptr += ml2;
          }
        }
      }
    } else {
      // Safe path for Sequence 1
      if (UNLIKELY(d_ptr + ll1 > d_end))
        return -1;
      memcpy(d_ptr, l_ptr, ll1);
      l_ptr += ll1;
      d_ptr += ll1;
      uint8_t *match_src1 = d_ptr - off1;
      if (UNLIKELY(match_src1 < dst || d_ptr + ml1 > d_end))
        return -1;
      if (off1 < ml1)
        for (size_t i = 0; i < ml1; i++)
          d_ptr[i] = match_src1[i];
      else
        memcpy(d_ptr, match_src1, ml1);
      d_ptr += ml1;

      // Safe path for Sequence 2
      if (UNLIKELY(d_ptr + ll2 > d_end))
        return -1;
      memcpy(d_ptr, l_ptr, ll2);
      l_ptr += ll2;
      d_ptr += ll2;
      uint8_t *match_src2 = d_ptr - off2;
      if (UNLIKELY(match_src2 < dst || d_ptr + ml2 > d_end))
        return -1;
      if (off2 < ml2)
        for (size_t i = 0; i < ml2; i++)
          d_ptr[i] = match_src2[i];
      else
        memcpy(d_ptr, match_src2, ml2);
      d_ptr += ml2;
    }
    n_seq -= 2;
  }

  if (n_seq) {
    uint8_t token = *t_ptr++;
    uint32_t ll = token >> 4;
    uint32_t ml = token & 0x0F;
    uint32_t off = zxc_le16(o_ptr);
    o_ptr += 2;

    if (UNLIKELY(ll == 15)) {
      ll = zxc_le32(e_ptr);
      e_ptr += 4;
    }
    if (UNLIKELY(ml == 15)) {
      ml = zxc_le32(e_ptr);
      e_ptr += 4;
    }
    ml += ZXC_LZ_MIN_MATCH;

    if (LIKELY(d_ptr + ll + ml < d_end_safe)) {
      const uint8_t *src_lit = l_ptr;
      uint8_t *dst_lit = d_ptr;
      uint8_t *target_lit_end = d_ptr + ll;
      do {
        zxc_copy16(dst_lit, src_lit);
        dst_lit += 16;
        src_lit += 16;
      } while (dst_lit < target_lit_end);
      d_ptr += ll;
      l_ptr += ll;

      uint8_t *match_src = d_ptr - off;
      if (off >= 16) {
        uint8_t *out = d_ptr;
        uint8_t *target_match_end = d_ptr + ml;
        do {
          zxc_copy16(out, match_src);
          out += 16;
          match_src += 16;
        } while (out < target_match_end);
        d_ptr += ml;
      } else {
        if (off == 1) {
          memset(d_ptr, match_src[0], ml);
          d_ptr += ml;
        } else {
          for (size_t i = 0; i < ml; i++)
            d_ptr[i] = match_src[i];
          d_ptr += ml;
        }
      }
    } else {
      if (UNLIKELY(d_ptr + ll > d_end))
        return -1;
      memcpy(d_ptr, l_ptr, ll);
      l_ptr += ll;
      d_ptr += ll;
      uint8_t *match_src = d_ptr - off;
      if (UNLIKELY(match_src < dst || d_ptr + ml > d_end))
        return -1;
      if (off < ml)
        for (size_t i = 0; i < ml; i++)
          d_ptr[i] = match_src[i];
      else
        memcpy(d_ptr, match_src, ml);
      d_ptr += ml;
    }
  }

  size_t generated = d_ptr - dst;
  if (generated < expected_raw_size) {
    size_t rem = expected_raw_size - generated;
    if (UNLIKELY(d_ptr + rem > d_end))
      return -1;
    memcpy(d_ptr, l_ptr, rem);
    d_ptr += rem;
  }
  return (int)(d_ptr - dst);
}

/**
 * @brief Decompresses a single chunk of data based on its block header.
 *
 * This internal wrapper function reads the block header from the source buffer
 * to determine the compression type (RAW, NUM, or GNR) and flags (such as
 * checksum presence). It then dispatches the decompression to the appropriate
 * specific decoder.
 *
 * If a checksum flag is present in the header and checksum verification is
 * enabled in the context, the function verifies the integrity of the
 * decompressed data against the stored CRC.
 *
 * @param ctx Pointer to the decompression context (zxc_cctx_t), used for
 * configuration like checksums.
 * @param src Pointer to the source buffer containing the compressed block
 * (including header).
 * @param src_sz Size of the source buffer in bytes.
 * @param dst Pointer to the destination buffer where decompressed data will be
 * written.
 * @param dst_cap Capacity of the destination buffer in bytes.
 *
 * @return The size of the decompressed data in bytes on success, or -1 if an
 * error occurs (e.g., invalid header, buffer overflow, unknown block type, or
 * checksum mismatch).
 */
int zxc_decompress_chunk_wrapper(zxc_cctx_t *ctx, const uint8_t *src,
                                 size_t src_sz, uint8_t *dst, size_t dst_cap) {
  zxc_block_header_t bh;
  if (zxc_read_block_header(src, src_sz, &bh) != 0)
    return -1;
  int has_crc = (bh.block_flags & ZXC_BLOCK_FLAG_CHECKSUM);
  size_t over = ZXC_BLOCK_HEADER_SIZE + (has_crc ? 4 : 0);
  const uint8_t *data = src + over;

  int decoded_sz = -1;
  if (bh.block_type == ZXC_BLOCK_RAW) {
    if (bh.raw_size > dst_cap)
      return -1;
    memcpy(dst, data, bh.raw_size);
    decoded_sz = bh.raw_size;
  } else if (bh.block_type == ZXC_BLOCK_NUM) {
    decoded_sz =
        zxc_decode_block_num(data, bh.comp_size, dst, dst_cap, bh.raw_size);
  } else if (bh.block_type == ZXC_BLOCK_GNR) {
    decoded_sz =
        zxc_decode_block_gnr(data, bh.comp_size, dst, dst_cap, bh.raw_size);
  } else {
    return -1;
  }

  if (decoded_sz >= 0 && has_crc && ctx->checksum_enabled) {
    uint32_t stored = zxc_le32(src + ZXC_BLOCK_HEADER_SIZE);
    uint32_t calc = zxc_checksum(dst, (size_t)decoded_sz, 0);
    if (stored != calc) {
      fprintf(stderr, "Checkum Error: Stored %x vs Calc %x\n", stored, calc);
      return -1;
    }
  }
  return decoded_sz;
}

/**
 * @brief Decompresses a data stream from an input file to an output file.
 *
 * This function acts as a high-level wrapper for the ZXC stream engine,
 * configured specifically for decompression. It processes the input stream
 * using the specified number of threads and optionally verifies the data
 * integrity using a checksum.
 *
 * @param f_in      Pointer to the input file stream containing compressed data.
 * @param f_out     Pointer to the output file stream where decompressed data
 * will be written.
 * @param n_threads The number of worker threads to use for parallel
 * decompression.
 * @param checksum  Flag indicating whether to verify the checksum of the data
 * (1 to enable, 0 to disable).
 * @return          Returns 0 on success, or a non-zero error code if the
 * decompression fails.
 */
int zxc_stream_decompress(FILE *f_in, FILE *f_out, int n_threads,
                          int checksum) {
  return zxc_stream_engine_run(f_in, f_out, n_threads, 0, 5, checksum,
                               zxc_decompress_chunk_wrapper);
}
/*
 * Copyright (c) 2025, Bertrand Lebonnois
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include "../../include/zxc.h"
#include "zxc_internal.h"

#define ZXC_NUM_FRAME_SIZE 128
#define ZXC_EPOCH_BITS 14
#define ZXC_OFFSET_MASK ((1U << (32 - ZXC_EPOCH_BITS)) - 1)
#define ZXC_MAX_EPOCH (1U << ZXC_EPOCH_BITS)

/**
 * @brief Encodes a block of numerical data using delta encoding and
 * bit-packing.
 *
 * This function compresses a source buffer of 32-bit integers. It processes the
 * data in frames defined by `ZXC_NUM_FRAME_SIZE`. For each frame, it calculates
 * the delta between consecutive values (using SIMD AVX2 instructions if
 * available and applicable), applies ZigZag encoding to map signed deltas to
 * unsigned integers, determines the minimum bit-width required for the frame,
 * and packs the bits.
 *
 * The output format consists of a block header, an optional checksum, a
 * numerical header, and a sequence of compressed frames. Each compressed frame
 * includes metadata (frame count, bit width, base value, packed size) followed
 * by the bit-packed stream.
 *
 * @param src Pointer to the source buffer containing raw 32-bit integer data.
 * @param src_size Size of the source buffer in bytes. Must be a multiple of 4
 * and non-zero.
 * @param dst Pointer to the destination buffer where compressed data will be
 * written.
 * @param dst_cap Capacity of the destination buffer in bytes.
 * @param out_sz Pointer to a variable where the total size of the compressed
 * output will be stored.
 * @param chk Flag indicating whether to calculate and store a checksum (1 to
 * enable, 0 to disable).
 * @param p_crc Pointer to a variable to store the calculated XXH32 checksum (if
 * `chk` is enabled).
 *
 * @return 0 on success, or -1 on failure (e.g., invalid input size, destination
 * buffer too small).
 */
static int zxc_encode_block_num(const uint8_t *src, size_t src_size,
                                uint8_t *dst, size_t dst_cap, size_t *out_sz,
                                int chk, uint32_t *p_crc) {
  if (src_size % 4 != 0 || src_size == 0)
    return -1;
  if (chk && p_crc)
    *p_crc = zxc_checksum(src, src_size, 0);

  size_t count = src_size / 4;
  size_t h_gap = ZXC_BLOCK_HEADER_SIZE + (chk ? 4 : 0);

  if (UNLIKELY(dst_cap < h_gap + ZXC_NUM_HEADER_BINARY_SIZE))
    return -1;

  zxc_block_header_t bh = {.block_type = ZXC_BLOCK_NUM,
                           .raw_size = (uint32_t)src_size};
  uint8_t *p_curr = dst + h_gap;
  size_t rem = dst_cap - h_gap;
  zxc_num_header_t nh = {.n_values = count, .frame_size = ZXC_NUM_FRAME_SIZE};

  int hs = zxc_write_num_header(p_curr, rem, &nh);
  if (UNLIKELY(hs < 0))
    return -1;

  p_curr += hs;
  rem -= hs;

  uint32_t deltas[ZXC_NUM_FRAME_SIZE];
  const uint8_t *in_ptr = src;
  uint32_t prev = 0;

  for (size_t i = 0; i < count; i += ZXC_NUM_FRAME_SIZE) {
    size_t frames =
        (count - i < ZXC_NUM_FRAME_SIZE) ? (count - i) : ZXC_NUM_FRAME_SIZE;
    uint32_t max_d = 0, base = prev;
    size_t j = 0;
#if defined(ZXC_USE_AVX2)
    if (frames >= 8) {
      for (; j < (frames & ~7); j += 8) {
        if (i == 0 && j == 0)
          goto _scalar;
        __m256i vc = _mm256_loadu_si256((const __m256i *)(in_ptr + j * 4));
        __m256i vp = _mm256_loadu_si256((const __m256i *)(in_ptr + j * 4 - 4));
        __m256i diff = _mm256_sub_epi32(vc, vp);
        _mm256_storeu_si256((__m256i *)&deltas[j],
                            _mm256_xor_si256(_mm256_slli_epi32(diff, 1),
                                             _mm256_srai_epi32(diff, 31)));
      }
    }
#endif
  _scalar:
#ifndef _MSC_VER
    __attribute__((unused));
#endif
    for (; j < frames; j++) {
      uint32_t v = zxc_le32(in_ptr + j * 4);
      deltas[j] = zxc_zigzag_encode((int32_t)(v - prev));
      prev = v;
    }
    for (size_t k = 0; k < frames; k++)
      if (deltas[k] > max_d)
        max_d = deltas[k];

    if (frames > 0)
      prev = zxc_le32(in_ptr + (frames - 1) * 4);
    in_ptr += frames * 4;

    uint8_t bits = zxc_highbit32(max_d);
    size_t packed = ((frames * bits) + 7) / 8;
    if (UNLIKELY(rem < 16 + packed))
      return -1;

    zxc_store_le16(p_curr, (uint16_t)frames);
    zxc_store_le16(p_curr + 2, bits);
    zxc_store_le64(p_curr + 4, (uint64_t)base);
    zxc_store_le32(p_curr + 12, (uint32_t)packed);

    p_curr += 16;
    rem -= 16;

    int pb = zxc_bitpack_stream_32(deltas, frames, p_curr, rem, bits);
    if (UNLIKELY(pb < 0))
      return -1;
    p_curr += pb;
    rem -= pb;
  }

  uint32_t p_sz = (uint32_t)(p_curr - (dst + h_gap));
  int hw = zxc_write_block_header(dst, dst_cap, &bh);
  if (chk)
    bh.block_flags |= ZXC_BLOCK_FLAG_CHECKSUM;
  else
    bh.block_flags &= ~ZXC_BLOCK_FLAG_CHECKSUM;

  bh.comp_size = p_sz;
  hw = zxc_write_block_header(dst, dst_cap, &bh);
  if (chk)
    zxc_store_le32(dst + hw, *p_crc);
  *out_sz = hw + (chk ? 4 : 0) + p_sz;
  return 0;
}

/**
 * @brief Encodes a data block using the General (GNR) compression format.
 *
 * This function implements the core LZ77 compression logic. It dynamically
 * adjusts compression parameters (search depth, lazy matching strategy, and
 * step skipping) based on the compression level configured in the context.
 *
 * The encoding process consists of:
 * 1. **LZ77 Parsing**: The function iterates through the source data,
 * maintaining a hash chain to find repeated patterns (matches). It supports
 * "Lazy Matching" for higher compression levels to optimize match selection.
 * 2. **Sequence Storage**: Matches are converted into sequences consisting of
 *    literal lengths, match lengths, and offsets.
 * 3. **Bitpacking & Serialization**: The sequences are analyzed to determine
 * optimal bit-widths. The function then writes the block header, encodes
 * literals (using Raw or RLE encoding), and bit-packs the sequence streams into
 * the destination buffer.
 *
 * @param ctx       Pointer to the compression context containing hash tables
 * and configuration.
 * @param src       Pointer to the input source data.
 * @param src_size  Size of the input data in bytes.
 * @param dst       Pointer to the destination buffer where compressed data will
 * be written.
 * @param dst_cap   Maximum capacity of the destination buffer.
 * @param out_sz    [Out] Pointer to a variable that will receive the total size
 * of the compressed output.
 * @param chk       Boolean flag; if non-zero, a checksum (CRC32) is calculated
 * and stored in the block header.
 * @param p_crc     [Out] Optional pointer to store the calculated CRC32 value
 * (can be NULL).
 *
 * @return 0 on success, or -1 if an error occurs (e.g., buffer overflow).
 */
static int zxc_encode_block_gnr(zxc_cctx_t *ctx, const uint8_t *src,
                                size_t src_size, uint8_t *dst, size_t dst_cap,
                                size_t *out_sz, int chk, uint32_t *p_crc) {
  int search_depth;
  int use_lazy;
  int min_match = ZXC_LZ_MIN_MATCH;

  // Parameter tuning based on levels (1-9)
  // Categories: 1-3 (Fast), 4-6 (Balanced), 7-9 (Strong)
  if (ctx->compression_level <= 3) {
    search_depth = 4; // Reduced depth for speed (Target < 47)
    use_lazy = 0;
  } else if (ctx->compression_level <= 6) {
    search_depth = 4; // Lazy enabled (Target < 45)
    use_lazy = 1;
  } else {
    search_depth = 1024; // Deep search
    use_lazy = 1;
  }

  ctx->epoch++;
  if (UNLIKELY(ctx->epoch >= ZXC_MAX_EPOCH)) {
    memset(ctx->hash_table, 0, 2 * ZXC_LZ_HASH_SIZE * sizeof(uint32_t));
    ctx->epoch = 1;
  }
  const uint32_t epoch_mark = ctx->epoch << (32 - ZXC_EPOCH_BITS);
  const uint8_t *ip = src, *iend = src + src_size, *anchor = ip,
                *mflimit = iend - 12;

  uint32_t seq_c = 0;
  size_t lit_c = 0;
  if (chk && p_crc)
    *p_crc = zxc_checksum(src, src_size, 0);

  uint32_t miss_count = 0; // Dynamic acceleration counter

  // Pre-calculate acceleration parameters
  // L1-3: Standard acceleration (shift 3) as per l1_3 tuning
  // L4-9: Aggressive acceleration (shift 4, trigger 16) to reach +30% speed
  const int accel_shift = (ctx->compression_level <= 3) ? 3 : 4;
  const int accel_cap = (ctx->compression_level <= 3) ? 32 : 6;
  const int accel_trigger = (ctx->compression_level <= 3) ? 8 : 16;

  while (LIKELY(ip < mflimit)) {
    // Branchless Acceleration
    size_t step = 1 + (miss_count >> accel_shift);
    if (step > accel_cap)
      step = accel_cap;

    if (UNLIKELY(ip + step >= mflimit)) {
      ip += step;
      continue;
    }

    ZXC_PREFETCH_READ(ip + step * 4 + 64);

    uint32_t cur_val = zxc_le32(ip);
    uint32_t h = zxc_hash_func(cur_val) & (ZXC_LZ_HASH_SIZE - 1);
    int32_t cur_pos = (uint32_t)(ip - src);

    uint32_t raw_head = ctx->hash_table[2 * h];
    uint32_t match_idx = (raw_head & ~ZXC_OFFSET_MASK) == epoch_mark
                             ? (raw_head & ZXC_OFFSET_MASK)
                             : 0;

    ctx->hash_table[2 * h] = epoch_mark | cur_pos;
    ctx->chain_table[cur_pos] = match_idx;

    const uint8_t *best_ref = NULL;
    uint32_t best_len = min_match - 1;

    // Dynamic Search Depth: If we are skipping (accelerating), don't search
    // deep
    int current_depth = (miss_count > 32) ? 2 : search_depth;

    // Unrolled Search Loop (4x unroll for common case)
    // We must continue searching to find the BEST match, not just the first
    // one.

    int attempts = current_depth;

    // Helper macro for match checking
    // Helper macro for match checking
#define CHECK_MATCH(m_idx, uid)                                                \
  if (m_idx > 0) {                                                             \
    if (cur_pos - m_idx < ZXC_LZ_MAX_DIST) {                                   \
      const uint8_t *ref = src + m_idx;                                        \
      if (zxc_le32(ref) == cur_val && ref[best_len] == ip[best_len]) {         \
        uint32_t mlen = 4;                                                     \
        const uint8_t *limit_8 = iend - 8;                                     \
        while (ip + mlen < limit_8) {                                          \
          if (zxc_le64(ip + mlen) == zxc_le64(ref + mlen))                     \
            mlen += 8;                                                         \
          else {                                                               \
            mlen += (__builtin_ctzll(zxc_le64(ip + mlen) ^                     \
                                     zxc_le64(ref + mlen)) >>                  \
                     3);                                                       \
            goto _match_len_done_##uid;                                        \
          }                                                                    \
        }                                                                      \
        while (ip + mlen < iend && ref[mlen] == ip[mlen])                      \
          mlen++;                                                              \
        _match_len_done_##uid : if (mlen > best_len) {                         \
          best_len = mlen;                                                     \
          best_ref = ref;                                                      \
          if (best_len >= 128)                                                 \
            goto _search_done;                                                 \
        }                                                                      \
      }                                                                        \
      m_idx = ctx->chain_table[m_idx];                                         \
    } else                                                                     \
      m_idx = 0;                                                               \
  }

    // Unroll 4 times
    if (attempts > 0) {
      CHECK_MATCH(match_idx, 1);
      attempts--;
    }
    if (attempts > 0) {
      CHECK_MATCH(match_idx, 2);
      attempts--;
    }
    if (attempts > 0) {
      CHECK_MATCH(match_idx, 3);
      attempts--;
    }
    if (attempts > 0) {
      CHECK_MATCH(match_idx, 4);
      attempts--;
    }

    // Fallback loop
    while (match_idx > 0 && attempts-- > 0) {
      CHECK_MATCH(match_idx, 99);
    }

  _search_done:;

#undef CHECK_MATCH
    if (use_lazy && best_ref && best_len < 32 &&
        ip + 1 < mflimit) { // Only lazy if match is short
      uint32_t next_val = zxc_le32(ip + 1);
      uint32_t h2 = zxc_hash_func(next_val) & (ZXC_LZ_HASH_SIZE - 1);
      uint32_t next_head = ctx->hash_table[2 * h2];
      uint32_t next_idx = (next_head & ~ZXC_OFFSET_MASK) == epoch_mark
                              ? (next_head & ZXC_OFFSET_MASK)
                              : 0;
      uint32_t max_lazy = 0;
      int lazy_att =
          (miss_count > 16) ? 2 : 8; // Reduce lazy effort if accelerating

      while (next_idx > 0 && lazy_att-- > 0) {
        if ((uint32_t)(ip + 1 - src) - next_idx >= ZXC_LZ_MAX_DIST)
          break;
        const uint8_t *ref2 = src + next_idx;
        if (zxc_le32(ref2) == next_val) {
          uint32_t l2 = 4;
          while (ip + 1 + l2 < iend && ref2[l2] == ip[1 + l2])
            l2++;
          if (l2 > max_lazy)
            max_lazy = l2;
        }
        next_idx = ctx->chain_table[next_idx];
      }
      if (max_lazy > best_len + 1)
        best_ref = NULL;
    }

    if (best_ref) {
      miss_count = 0; // Reset acceleration on match
      while (ip > anchor && best_ref > src && ip[-1] == best_ref[-1]) {
        ip--;
        best_ref--;
        best_len++;
      }

      if (seq_c < ctx->max_seq_count) {
        ctx->sequences[seq_c].lit_len = (uint32_t)(ip - anchor);
        ctx->sequences[seq_c].match_len =
            (uint32_t)(best_len - ZXC_LZ_MIN_MATCH);
        ctx->sequences[seq_c].offset = (uint32_t)(ip - best_ref);
        if (ctx->sequences[seq_c].lit_len > 0) {
          memcpy(ctx->literals + lit_c, anchor, ctx->sequences[seq_c].lit_len);
          lit_c += ctx->sequences[seq_c].lit_len;
        }
        seq_c++;
      } else {
        ip += best_len;
        anchor = ip;
        break;
      }
      ip += best_len;
      anchor = ip;
    } else {
      miss_count++; // Increment acceleration counter
      ip += step;
    }
  }

  size_t last_lits = iend - anchor;
  if (last_lits > 0) {
    memcpy(ctx->literals + lit_c, anchor, last_lits);
    lit_c += last_lits;
  }

  // --- TOKEN ENCODING ---
  uint8_t *buf_tokens = (uint8_t *)ctx->buf_off;   // Reuse buf_off for tokens
  uint16_t *buf_offsets = (uint16_t *)ctx->buf_ml; // Reuse buf_ml for offsets
  uint32_t *buf_extras = ctx->buf_ll;              // Reuse buf_ll for extras
  size_t n_extras = 0;

  for (uint32_t i = 0; i < seq_c; i++) {
    uint32_t ll = ctx->sequences[i].lit_len;
    uint32_t ml = ctx->sequences[i].match_len;
    uint32_t off = ctx->sequences[i].offset;

    uint8_t ll_code = (ll >= 15) ? 15 : (uint8_t)ll;
    uint8_t ml_code = (ml >= 15) ? 15 : (uint8_t)ml;

    buf_tokens[i] = (ll_code << 4) | ml_code;
    buf_offsets[i] = (uint16_t)off;

    if (ll >= 15)
      buf_extras[n_extras++] = ll;
    if (ml >= 15)
      buf_extras[n_extras++] = ml;
  }

  size_t h_gap = ZXC_BLOCK_HEADER_SIZE + (chk ? 4 : 0);
  zxc_block_header_t bh = {.block_type = ZXC_BLOCK_GNR,
                           .raw_size = (uint32_t)src_size};
  uint8_t *p = dst + h_gap;
  size_t rem = dst_cap - h_gap;

  zxc_gnr_header_t gh = {.n_sequences = seq_c,
                         .n_literals = (uint32_t)lit_c,
                         .enc_lit = 0,
                         .enc_litlen = 0,
                         .enc_mlen = 0,
                         .enc_off = 0};

  zxc_section_desc_t desc[4] = {0};
  desc[0].comp_size = (uint32_t)lit_c;
  desc[0].raw_size = (uint32_t)lit_c;
  desc[1].comp_size = seq_c;
  desc[1].raw_size = seq_c;
  desc[2].comp_size = seq_c * 2;
  desc[2].raw_size = seq_c * 2;
  desc[3].comp_size = (uint32_t)(n_extras * 4);
  desc[3].raw_size = (uint32_t)(n_extras * 4);

  int ghs = zxc_write_gnr_header_and_desc(p, rem, &gh, desc);
  if (UNLIKELY(ghs < 0))
    return -1;

  uint8_t *p_curr = p + ghs;
  rem -= ghs;

  if (rem < desc[0].comp_size)
    return -1;
  memcpy(p_curr, ctx->literals, lit_c);
  p_curr += lit_c;
  rem -= lit_c;

  if (rem < desc[1].comp_size)
    return -1;
  memcpy(p_curr, buf_tokens, seq_c);
  p_curr += seq_c;
  rem -= seq_c;

  if (rem < desc[2].comp_size)
    return -1;
  memcpy(p_curr, buf_offsets, seq_c * 2);
  p_curr += seq_c * 2;
  rem -= seq_c * 2;

  if (rem < desc[3].comp_size)
    return -1;
  memcpy(p_curr, buf_extras, n_extras * 4);
  p_curr += n_extras * 4;
  rem -= n_extras * 4;

  uint32_t p_sz = (uint32_t)(p_curr - (dst + h_gap));
  if (chk)
    bh.block_flags |= ZXC_BLOCK_FLAG_CHECKSUM;
  else
    bh.block_flags &= ~ZXC_BLOCK_FLAG_CHECKSUM;

  bh.comp_size = p_sz;
  int wh = zxc_write_block_header(dst, dst_cap, &bh);
  if (chk)
    zxc_store_le32(dst + wh, *p_crc);
  *out_sz = wh + (chk ? 4 : 0) + p_sz;
  return 0;
}

static int zxc_encode_block_lz(zxc_cctx_t *ctx, const uint8_t *src,
                               size_t src_size, uint8_t *dst, size_t dst_cap,
                               size_t *out_sz, int chk, uint32_t *p_crc) {
  // --- SETUP PARAMETERS ---
  // Calculate acceleration based on compression level (lower level = faster
  // skip) Level 1: accel 2, Level >= 5: accel 1 (standard)
  uint32_t acceleration =
      (ctx->compression_level < 5) ? ((5 - ctx->compression_level) / 2) + 1 : 1;

  // Manage Epoch for Hash Table (avoids memset)
  ctx->epoch++;
  if (UNLIKELY(ctx->epoch >= ZXC_MAX_EPOCH)) {
    memset(ctx->hash_table, 0, 2 * ZXC_LZ_HASH_SIZE * sizeof(uint32_t));
    ctx->epoch = 1;
  }
  const uint32_t epoch_mark = ctx->epoch << (32 - ZXC_EPOCH_BITS);

  // --- POINTERS ---
  const uint8_t *ip = src;
  const uint8_t *const iend = src + src_size;
  const uint8_t *const mflimit =
      iend - 12; // Match Find Limit (need 12 bytes margin)
  const uint8_t *anchor = ip;

  uint32_t seq_c = 0;
  size_t lit_c = 0;

  // Checksum init
  if (chk && p_crc)
    *p_crc = zxc_checksum(src, src_size, 0);

  // --- MAIN COMPRESSION LOOP (LZ4 STYLE) ---
  uint32_t forwardH;
  uint32_t miss_count = 0;

  // Initial Hash
  if (src_size > 4) {
    forwardH = zxc_hash_func(zxc_le32(ip)) & (ZXC_LZ_HASH_SIZE - 1);
  }

  while (LIKELY(ip < mflimit)) {
    const uint8_t *match;
    uint32_t match_idx;
    size_t forward_step = 0;

    // 1. SEARCH LOOP
    // Skip positions until a potential match is found in the hash table
    do {
      ip += forward_step;
      if (ctx->compression_level < 7) {
        miss_count++;
        // Heuristique LZ4 : on augmente le pas de 1 tous les 32 échecs (>> 5)
        forward_step = 1 + (miss_count >> 5); // 1 + (miss_count >> 5);
      } else {
        forward_step = 1; // 1
      }

      if (UNLIKELY(ip >= mflimit))
        goto _end_of_loop;

      uint32_t h = forwardH;
      // uint32_t val = zxc_le32(ip);

      // Prepare hash for next step (pipelining)
      forwardH =
          zxc_hash_func(zxc_le32(ip + forward_step)) & (ZXC_LZ_HASH_SIZE - 1);

      // Lookup in table
      uint32_t raw_head = ctx->hash_table[2 * h];
      match_idx = (raw_head & ~ZXC_OFFSET_MASK) == epoch_mark
                      ? (raw_head & ZXC_OFFSET_MASK)
                      : 0;

      // Update table immediately (overwriting old entry - no chains)
      ctx->hash_table[2 * h] = epoch_mark | (uint32_t)(ip - src);

      match = src + match_idx;

      // Check validity:
      // A. Index must be non-zero (valid within epoch)
      // B. Distance must be < MAX_DIST
      // C. Values must match
    } while (match_idx == 0 ||
             (uint32_t)(ip - src) - match_idx >= ZXC_LZ_MAX_DIST ||
             zxc_le32(match) != zxc_le32(ip));

    // 2. MATCH FOUND
    miss_count = 0;

    // A. Extend Backwards
    // Try to catch up literals that match before the current point
    while (ip > anchor && match > src && ip[-1] == match[-1]) {
      ip--;
      match--;
    }

    // B. Encode Sequence
    uint32_t lit_len = (uint32_t)(ip - anchor);
    uint32_t offset = (uint32_t)(ip - match);

    // Store literals
    if (lit_len > 0) {
      memcpy(ctx->literals + lit_c, anchor, lit_len);
      lit_c += lit_len;
    }

    // C. Extend Forwards (Find Match Length)
    // Using the existing SIMD optimized logic from your file
    uint32_t match_len = 4;
    {
      const uint8_t *ref = match;
      // SIMD Comparison Block (Keep existing optimization)
#if defined(XZK_USE_AVX512)
      const uint8_t *limit_64 = iend - 64;
      while (ip + match_len < limit_64) {
        __m512i v_src = _mm512_loadu_si512((const void *)(ip + match_len));
        __m512i v_ref = _mm512_loadu_si512((const void *)(ref + match_len));
        __mmask64 mask = _mm512_cmpeq_epi8_mask(v_src, v_ref);
        if (mask == 0xFFFFFFFFFFFFFFFF)
          match_len += 64;
        else {
          match_len += (uint32_t)__builtin_ctzll(~mask);
          goto _match_len_done;
        }
      }
#elif defined(ZXC_USE_AVX2)
      const uint8_t *limit_32 = iend - 32;
      while (ip + match_len < limit_32) {
        __m256i v_src = _mm256_loadu_si256((const __m256i *)(ip + match_len));
        __m256i v_ref = _mm256_loadu_si256((const __m256i *)(ref + match_len));
        __m256i v_cmp = _mm256_cmpeq_epi8(v_src, v_ref);
        uint32_t mask = (uint32_t)_mm256_movemask_epi8(v_cmp);
        if (mask == 0xFFFFFFFF)
          match_len += 32;
        else {
          match_len += __builtin_ctz(~mask);
          goto _match_len_done;
        }
      }
#endif
      // Scalar fallback
      const uint8_t *limit_8 = iend - 8;
      while (ip + match_len < limit_8) {
        if (zxc_le64(ip + match_len) == zxc_le64(ref + match_len))
          match_len += 8;
        else {
          match_len += (__builtin_ctzll(zxc_le64(ip + match_len) ^
                                        zxc_le64(ref + match_len)) >>
                        3);
          goto _match_len_done;
        }
      }
      while (ip + match_len < iend && ref[match_len] == ip[match_len])
        match_len++;
    _match_len_done:;
    }

    // Save Sequence info
    if (seq_c < ctx->max_seq_count) {
      ctx->sequences[seq_c].lit_len = lit_len;
      ctx->sequences[seq_c].match_len = match_len - ZXC_LZ_MIN_MATCH;
      ctx->sequences[seq_c].offset = offset;
      seq_c++;
    } else {
      // Buffer full, treat rest as literals (should rarely happen with proper
      // sizing)
      ip += match_len;
      anchor = ip;
      break;
    }

    ip += match_len;
    anchor = ip;

    // D. Prepare for next search
    // Calculate hash for the NEW position to prime the next loop iteration
    if (ip < mflimit) {
      forwardH = zxc_hash_func(zxc_le32(ip)) & (ZXC_LZ_HASH_SIZE - 1);
    }
  }

_end_of_loop:;
  // --- FINISH UP (SERIALIZATION) ---
  // Copy remaining literals
  size_t last_lits = iend - anchor;
  if (last_lits > 0) {
    memcpy(ctx->literals + lit_c, anchor, last_lits);
    lit_c += last_lits;
  }

  // --- TOKEN ENCODING (UNCHANGED FROM ORIGINAL) ---
  uint8_t *buf_tokens = (uint8_t *)ctx->buf_off;   // Reuse buf_off
  uint16_t *buf_offsets = (uint16_t *)ctx->buf_ml; // Reuse buf_ml
  uint32_t *buf_extras = ctx->buf_ll;              // Reuse buf_ll
  size_t n_extras = 0;

  for (uint32_t i = 0; i < seq_c; i++) {
    uint32_t ll = ctx->sequences[i].lit_len;
    uint32_t ml = ctx->sequences[i].match_len;
    uint32_t off = ctx->sequences[i].offset;

    uint8_t ll_code = (ll >= 15) ? 15 : (uint8_t)ll;
    uint8_t ml_code = (ml >= 15) ? 15 : (uint8_t)ml;

    buf_tokens[i] = (ll_code << 4) | ml_code;
    buf_offsets[i] = (uint16_t)off;

    if (ll >= 15)
      buf_extras[n_extras++] = ll;
    if (ml >= 15)
      buf_extras[n_extras++] = ml;
  }

  // --- WRITE HEADERS ---
  size_t h_gap = ZXC_BLOCK_HEADER_SIZE + (chk ? 4 : 0);
  zxc_block_header_t bh = {.block_type = ZXC_BLOCK_GNR,
                           .raw_size = (uint32_t)src_size};
  uint8_t *p = dst + h_gap;
  size_t rem = dst_cap - h_gap;

  zxc_gnr_header_t gh = {.n_sequences = seq_c,
                         .n_literals = (uint32_t)lit_c,
                         .enc_lit = 0,
                         .enc_litlen = 0,
                         .enc_mlen = 0,
                         .enc_off = 0};

  zxc_section_desc_t desc[4] = {0};
  desc[0].comp_size = (uint32_t)lit_c;
  desc[0].raw_size = (uint32_t)lit_c;
  desc[1].comp_size = seq_c;
  desc[1].raw_size = seq_c;
  desc[2].comp_size = seq_c * 2;
  desc[2].raw_size = seq_c * 2;
  desc[3].comp_size = (uint32_t)(n_extras * 4);
  desc[3].raw_size = (uint32_t)(n_extras * 4);

  int ghs = zxc_write_gnr_header_and_desc(p, rem, &gh, desc);
  if (UNLIKELY(ghs < 0))
    return -1;

  uint8_t *p_curr = p + ghs;
  rem -= ghs;

  // --- WRITE STREAMS ---
  if (rem < desc[0].comp_size)
    return -1;
  memcpy(p_curr, ctx->literals, lit_c);
  p_curr += lit_c;
  rem -= lit_c;

  if (rem < desc[1].comp_size)
    return -1;
  memcpy(p_curr, buf_tokens, seq_c);
  p_curr += seq_c;
  rem -= seq_c;

  if (rem < desc[2].comp_size)
    return -1;
  memcpy(p_curr, buf_offsets, seq_c * 2);
  p_curr += seq_c * 2;
  rem -= seq_c * 2;

  if (rem < desc[3].comp_size)
    return -1;
  memcpy(p_curr, buf_extras, n_extras * 4);
  p_curr += n_extras * 4;
  rem -= n_extras * 4;

  // --- FINALIZE BLOCK ---
  uint32_t p_sz = (uint32_t)(p_curr - (dst + h_gap));
  if (chk)
    bh.block_flags |= ZXC_BLOCK_FLAG_CHECKSUM;
  else
    bh.block_flags &= ~ZXC_BLOCK_FLAG_CHECKSUM;

  bh.comp_size = p_sz;
  int wh = zxc_write_block_header(dst, dst_cap, &bh);
  if (chk)
    zxc_store_le32(dst + wh, *p_crc);
  *out_sz = wh + (chk ? 4 : 0) + p_sz;
  return 0;
}
/**
 * @brief Encodes a raw data block (uncompressed).
 *
 * This function prepares and writes a "RAW" type block into the destination
 * buffer. It handles the block header, copying of source data, and optionally
 * the calculation and storage of a checksum.
 *
 * @param src Pointer to the source data to encode.
 * @param sz Size of the source data in bytes.
 * @param dst Pointer to the destination buffer.
 * @param cap Maximum capacity of the destination buffer.
 * @param out_sz Pointer to a variable receiving the total written size (header
 * + data + checksum).
 * @param chk Boolean flag: if non-zero, a checksum is calculated and added.
 * @param p_crc Pointer to store or retrieve the calculated CRC value (used if
 * chk is active).
 *
 * @return 0 on success, -1 if the destination buffer capacity is insufficient.
 */
static int zxc_encode_block_raw(const uint8_t *src, size_t sz, uint8_t *dst,
                                size_t cap, size_t *out_sz, int chk,
                                uint32_t *p_crc) {
  size_t h_gap = ZXC_BLOCK_HEADER_SIZE + (chk ? 4 : 0);
  if (UNLIKELY(cap < h_gap + sz))
    return -1;
  zxc_block_header_t bh = {.block_type = ZXC_BLOCK_RAW,
                           .raw_size = (uint32_t)sz};

  if (chk) {
    if (p_crc)
      *p_crc = zxc_copy_and_checksum(src, dst + h_gap, sz, 0);
    bh.block_flags |= ZXC_BLOCK_FLAG_CHECKSUM;
  } else {
    memcpy(dst + h_gap, src, sz);
    bh.block_flags &= ~ZXC_BLOCK_FLAG_CHECKSUM;
  }

  bh.comp_size = (uint32_t)sz;
  int wh = zxc_write_block_header(dst, cap, &bh);
  if (chk)
    zxc_store_le32(dst + wh, *p_crc);
  *out_sz = wh + (chk ? 4 : 0) + sz;
  return 0;
}

/**
 * @brief Calculates a quick 0-order entropy heuristic.
 *
 * This function is used to determine if a data block is likely incompressible
 * (e.g., encrypted data or already compressed data) before attempting
 * computationally expensive compression algorithms.
 *
 * @details
 * The heuristic estimates the randomness of the byte distribution. If the
 * entropy is above a certain threshold, the block is skipped to save processing
 * time.
 *
 * @note This is an estimation and not a precise entropy calculation.
 *
 * @param[in] data Pointer to the input data buffer.
 * @param[in] size Size of the input data in bytes.
 * @return A heuristic score indicating compressibility (lower means more
 * compressible).
 */
// Quick 0-order Entropy Heuristic to skip incompressible blocks (e.g.,
// encrypted data)
static int zxc_check_compressibility(const uint8_t *src, size_t src_size) {
  size_t step = 32;
  if (src_size < 2048)
    step = 1;
  else if (src_size < 8192)
    step = 8;

  uint32_t counts[256] = {0};
  size_t total_samples = 0;

  const uint8_t *p = src;
  const uint8_t *end = src + src_size;

  while (p < end) {
    counts[*p]++;
    p += step;
    total_samples++;
  }

  // Calculate sum of squares to estimate distribution uniformity
  uint64_t sum_sq = 0;
  for (int i = 0; i < 256; i++) {
    if (counts[i] > 0)
      sum_sq += (uint64_t)counts[i] * counts[i];
  }

  uint64_t threshold = (total_samples * total_samples) / 180;

  return (sum_sq > threshold);
}

/**
 * @brief Wraps the compression logic for a single chunk of data, selecting the
 * best encoding strategy.
 *
 * This function attempts to compress a given data chunk using different
 * strategies based on the data size and compressibility. It handles the
 * decision-making process between raw encoding, general-purpose compression
 * (GNR), and numerical compression (NUM).
 *
 * The logic flow is as follows:
 * 1. If the chunk size is large (>= 1024 bytes) and deemed incompressible by a
 * heuristic check, it defaults immediately to raw encoding.
 * 2. Otherwise, it attempts general-purpose compression (GNR).
 * 3. If GNR fails or results in a poor compression ratio (> 90%) for specific
 * block sizes, it attempts numerical compression (NUM).
 * 4. If numerical compression is successful and efficient, it is used.
 * 5. If all compression attempts fail or are inefficient, it falls back to raw
 * encoding.
 *
 * @param ctx Pointer to the ZXC compression context containing configuration
 * (e.g., checksum flags).
 * @param chunk Pointer to the source data buffer to be compressed.
 * @param sz Size of the source data chunk in bytes.
 * @param dst Pointer to the destination buffer where compressed data will be
 * written.
 * @param cap Capacity of the destination buffer.
 *
 * @return The size of the written data in bytes on success, or -1 if an error
 * occurred (e.g., buffer overflow or encoding failure).
 */
int zxc_compress_chunk_wrapper(zxc_cctx_t *ctx, const uint8_t *chunk, size_t sz,
                               uint8_t *dst, size_t cap) {
  int chk = ctx->checksum_enabled;

  // 1. Check for incompressibility (Heuristic)
  if (sz >= 1024) {
    if (!zxc_check_compressibility(chunk, sz)) {
      size_t w_raw = 0;
      uint32_t crc = 0;
      if (zxc_encode_block_raw(chunk, sz, dst, cap, &w_raw, chk, &crc) != 0)
        return -1;
      return (int)w_raw;
    }
  }

  size_t w = 0;
  uint32_t crc = 0;
  int res = -1;

  // 2. Block Selection Logic
  // Levels 1-3: Prefer speed. Use GNR with low settings (already configured in
  // zxc_encode_block_gnr). Levels 4-9: Use GNR with higher settings. NUM block:
  // Try if data looks numeric? For now, let's stick to GNR as primary, but we
  // can try NUM if GNR ratio is poor?

  // For now, we use the enhanced GNR for all levels as it now supports dynamic
  // acceleration and levels. zxc_encode_block_lz is legacy/alternative, but GNR
  // is more flexible.

  res = zxc_encode_block_gnr(ctx, chunk, sz, dst, cap, &w, chk, &crc);

  // 3. Fallback to RAW if compression expanded data
  if (res != 0 || w >= sz) {
    size_t w_raw = 0;
    if (zxc_encode_block_raw(chunk, sz, dst, cap, &w_raw, chk, &crc) != 0)
      return -1;
    return (int)w_raw;
  }

  return (int)w;
}

/**
 * @brief Compresses a data stream from an input file to an output file.
 *
 * This function initializes the compression engine to process the input stream
 * using the specified number of threads and compression level. It acts as a
 * wrapper around the generic stream engine, specifically configuring it for
 * compression operations.
 *
 * @param f_in      Pointer to the input file stream to be compressed.
 * @param f_out     Pointer to the output file stream where compressed data will
 * be written.
 * @param n_threads The number of threads to use for parallel compression.
 * @param level     The compression level (determines the trade-off between
 * speed and ratio).
 * @param checksum  Flag indicating whether to calculate and store a checksum
 * for data integrity.
 *
 * @return          Returns 0 on success, or a non-zero error code on failure.
 */
int zxc_stream_compress(FILE *f_in, FILE *f_out, int n_threads, int level,
                        int checksum) {
  return zxc_stream_engine_run(f_in, f_out, n_threads, 1, level, checksum,
                               zxc_compress_chunk_wrapper);
}
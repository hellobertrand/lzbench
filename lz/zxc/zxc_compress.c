/*
 * Copyright (c) 2025, Bertrand Lebonnois
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include "zxc.h"
#include "zxc_internal.h"

#define ZXC_NUM_FRAME_SIZE 128
#define ZXC_EPOCH_BITS 14
#define ZXC_OFFSET_MASK ((1U << (32 - ZXC_EPOCH_BITS)) - 1)
#define ZXC_MAX_EPOCH (1U << ZXC_EPOCH_BITS)

/**
 * @brief Encodes a block of numerical data using delta encoding and bit-packing.
 *
 * This function compresses a source buffer of 32-bit integers. It processes the data
 * in frames defined by `ZXC_NUM_FRAME_SIZE`. For each frame, it calculates the
 * delta between consecutive values (using SIMD AVX2 instructions if available and
 * applicable), applies ZigZag encoding to map signed deltas to unsigned integers,
 * determines the minimum bit-width required for the frame, and packs the bits.
 *
 * The output format consists of a block header, an optional checksum, a numerical
 * header, and a sequence of compressed frames. Each compressed frame includes metadata
 * (frame count, bit width, base value, packed size) followed by the bit-packed stream.
 *
 * @param src Pointer to the source buffer containing raw 32-bit integer data.
 * @param src_size Size of the source buffer in bytes. Must be a multiple of 4 and non-zero.
 * @param dst Pointer to the destination buffer where compressed data will be written.
 * @param dst_cap Capacity of the destination buffer in bytes.
 * @param out_sz Pointer to a variable where the total size of the compressed output will be stored.
 * @param chk Flag indicating whether to calculate and store a checksum (1 to enable, 0 to disable).
 * @param p_crc Pointer to a variable to store the calculated XXH32 checksum (if `chk` is enabled).
 *
 * @return 0 on success, or -1 on failure (e.g., invalid input size, destination buffer too small).
 */
static int zxc_encode_block_num(const uint8_t *src, size_t src_size, uint8_t *dst, size_t dst_cap,
                                size_t *out_sz, int chk, uint32_t *p_crc)
{
    if (src_size % 4 != 0 || src_size == 0)
        return -1;
    if (chk && p_crc)
        *p_crc = zxc_checksum(src, src_size, 0);

    size_t count = src_size / 4;
    size_t h_gap = ZXC_BLOCK_HEADER_SIZE + (chk ? 4 : 0);

    if (UNLIKELY(dst_cap < h_gap + ZXC_NUM_HEADER_BINARY_SIZE))
        return -1;

    zxc_block_header_t bh = {.block_type = ZXC_BLOCK_NUM, .raw_size = (uint32_t)src_size};
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

    for (size_t i = 0; i < count; i += ZXC_NUM_FRAME_SIZE)
    {
        size_t frames = (count - i < ZXC_NUM_FRAME_SIZE) ? (count - i) : ZXC_NUM_FRAME_SIZE;
        uint32_t max_d = 0, base = prev;
        size_t j = 0;
#if defined(ZXC_USE_AVX2)
        if (frames >= 8)
        {
            for (; j < (frames & ~7); j += 8)
            {
                if (i == 0 && j == 0)
                    goto _scalar;
                __m256i vc = _mm256_loadu_si256((const __m256i *)(in_ptr + j * 4));
                __m256i vp = _mm256_loadu_si256((const __m256i *)(in_ptr + j * 4 - 4));
                __m256i diff = _mm256_sub_epi32(vc, vp);
                _mm256_storeu_si256(
                    (__m256i *)&deltas[j],
                    _mm256_xor_si256(_mm256_slli_epi32(diff, 1), _mm256_srai_epi32(diff, 31)));
            }
        }
#endif
    _scalar:
#ifndef _MSC_VER
        __attribute__((unused));
#endif
        for (; j < frames; j++)
        {
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
 * This function implements the core LZ77 compression logic. It dynamically adjusts
 * compression parameters (search depth, lazy matching strategy, and step skipping)
 * based on the compression level configured in the context.
 *
 * The encoding process consists of:
 * 1. **LZ77 Parsing**: The function iterates through the source data, maintaining a
 *    hash chain to find repeated patterns (matches). It supports "Lazy Matching"
 *    for higher compression levels to optimize match selection.
 * 2. **Sequence Storage**: Matches are converted into sequences consisting of
 *    literal lengths, match lengths, and offsets.
 * 3. **Bitpacking & Serialization**: The sequences are analyzed to determine optimal
 *    bit-widths. The function then writes the block header, encodes literals (using
 *    Raw or RLE encoding), and bit-packs the sequence streams into the destination buffer.
 *
 * @param ctx       Pointer to the compression context containing hash tables and configuration.
 * @param src       Pointer to the input source data.
 * @param src_size  Size of the input data in bytes.
 * @param dst       Pointer to the destination buffer where compressed data will be written.
 * @param dst_cap   Maximum capacity of the destination buffer.
 * @param out_sz    [Out] Pointer to a variable that will receive the total size of the compressed
 * output.
 * @param chk       Boolean flag; if non-zero, a checksum (CRC32) is calculated and stored in the
 * block header.
 * @param p_crc     [Out] Optional pointer to store the calculated CRC32 value (can be NULL).
 *
 * @return 0 on success, or -1 if an error occurs (e.g., buffer overflow).
 */
static int zxc_encode_block_gnr(zxc_cctx_t *ctx, const uint8_t *src, size_t src_size, uint8_t *dst,
                                size_t dst_cap, size_t *out_sz, int chk, uint32_t *p_crc)
{
    int search_depth; // Maximum number of links to traverse in the hash chain
    int use_lazy;     // Enable "Lazy Matching" for better compression ratio
    int step_shift;   // Shift factor to calculate skip step on incompressible data

    if (ctx->compression_level <= 1)
    {
        search_depth = 0;
        use_lazy = 0;
        step_shift = 6;
    }
    else if (ctx->compression_level < 9)
    {
        search_depth = 4;
        use_lazy = 0;
        step_shift = 10; // Effectively step=1 most of the time
    }
    else
    {
        search_depth = 64;
        use_lazy = 1;
        step_shift = 12; // Always step=1
    }

    ctx->epoch++;
    if (UNLIKELY(ctx->epoch >= ZXC_MAX_EPOCH))
    {
        memset(ctx->hash_table, 0, 2 * ZXC_LZ_HASH_SIZE * sizeof(uint32_t));
        ctx->epoch = 1;
    }
    const uint32_t epoch_mark = ctx->epoch << (32 - ZXC_EPOCH_BITS);
    const uint8_t *ip = src, *iend = src + src_size, *anchor = ip, *mflimit = iend - 12;

    uint32_t seq_c = 0;
    size_t lit_c = 0;
    uint32_t crc_calc = 0;
    if (chk)
        crc_calc = zxc_checksum(src, src_size, 0);
    if (p_crc)
        *p_crc = crc_calc;

    while (LIKELY(ip < mflimit))
    {
        size_t step = 1;
        if (ctx->compression_level <= 5)
        {
            step = 1 + ((size_t)(ip - anchor) >> step_shift);
            if (UNLIKELY(ip + step >= mflimit))
                step = 1;
        }

        if (UNLIKELY(ip + step >= mflimit))
            step = 1;

        ZXC_PREFETCH_READ(ip + step * 4 + 64);

        uint32_t cur_val = zxc_le32(ip);
        uint32_t h = (cur_val * 2654435761U) >> (32 - ZXC_LZ_HASH_BITS);
        int32_t cur_pos = (uint32_t)(ip - src);

        uint32_t raw_head = ctx->hash_table[2 * h];
        uint32_t match_idx =
            (raw_head & ~ZXC_OFFSET_MASK) == epoch_mark ? (raw_head & ZXC_OFFSET_MASK) : 0;

        ctx->hash_table[2 * h] = epoch_mark | cur_pos;
        ctx->chain_table[cur_pos] = match_idx;

        const uint8_t *best_ref = NULL;
        uint32_t best_len = 3;

        int attempts = search_depth;
        while (match_idx > 0 && attempts-- >= 0)
        {
            if (cur_pos - match_idx >= ZXC_LZ_MAX_DIST)
                break;

            const uint8_t *ref = src + match_idx;

            if (zxc_le32(ref) == cur_val && ref[best_len] == ip[best_len])
            {
                uint32_t mlen = 4;
#if defined(XZK_USE_AVX512)
                const uint8_t *limit_64 = iend - 64;
                while (ip + mlen < limit_64)
                {
                    __m512i v_src = _mm512_loadu_si512((const void *)(ip + mlen));
                    __m512i v_ref = _mm512_loadu_si512((const void *)(ref + mlen));
                    // 64-bit mask where each bit set to 1 indicates equality
                    __mmask64 mask = _mm512_cmpeq_epi8_mask(v_src, v_ref);

                    if (mask == 0xFFFFFFFFFFFFFFFF)
                    {
                        mlen += 64; // Everything matches
                    }
                    else
                    {
                        // Count trailing zeros to find the first difference
                        // Note: __builtin_ctzll is GCC/Clang specific. On MSVC:
                        // _BitScanForward64
                        mlen += (uint32_t)__builtin_ctzll(~mask);
                        goto _match_len_done;
                    }
                }
#elif defined(XZK_USE_AVX2)
                const uint8_t *limit_32 = iend - 32;
                while (ip + mlen < limit_32)
                {
                    __m256i v_src = _mm256_loadu_si256((const __m256i *)(ip + mlen));
                    __m256i v_ref = _mm256_loadu_si256((const __m256i *)(ref + mlen));
                    __m256i v_cmp = _mm256_cmpeq_epi8(v_src, v_ref);
                    uint32_t mask = (uint32_t)_mm256_movemask_epi8(v_cmp);

                    if (mask == 0xFFFFFFFF)
                    {
                        mlen += 32;
                    }
                    else
                    {
                        mlen += __builtin_ctz(~mask);
                        goto _match_len_done;
                    }
                }
#elif defined(XZK_USE_NEON)
                const uint8_t *limit_16 = iend - 16;
                while (ip + mlen < limit_16)
                {
                    uint8x16_t v_src = vld1q_u8(ip + mlen);
                    uint8x16_t v_ref = vld1q_u8(ref + mlen);
                    // v_cmp contains 0xFF if equal, 0x00 otherwise
                    uint8x16_t v_cmp = vceqq_u8(v_src, v_ref);

                    // AArch64 optimization: vminvq_u8 returns the minimum value of the vector.
                    // If the minimum is 0xFF (255), it means ALL bytes are equal.
                    if (vminvq_u8(v_cmp) == 0xFF)
                    {
                        mlen += 16;
                    }
                    else
                    {
                        // Difference found. Invert to have 0xFF where it differs.
                        uint8x16_t v_diff = vmvnq_u8(v_cmp);

                        // Extract the lower 64 bits
                        uint64_t lo = vgetq_lane_u64(vreinterpretq_u64_u8(v_diff), 0);
                        if (lo != 0)
                        {
                            // __builtin_ctzll counts trailing zeros (Little Endian friendly)
                            mlen += (__builtin_ctzll(lo) >> 3);
                        }
                        else
                        {
                            // Otherwise it's in the high part
                            uint64_t hi = vgetq_lane_u64(vreinterpretq_u64_u8(v_diff), 1);
                            mlen += 8 + (__builtin_ctzll(hi) >> 3);
                        }
                        goto _match_len_done;
                    }
                }
#endif
                const uint8_t *limit_8 = iend - 8;
                while (ip + mlen < limit_8)
                {
                    if (zxc_le64(ip + mlen) == zxc_le64(ref + mlen))
                    {
                        mlen += 8;
                    }
                    else
                    {
                        mlen += (__builtin_ctzll(zxc_le64(ip + mlen) ^ zxc_le64(ref + mlen)) >> 3);
                        goto _match_len_done;
                    }
                }

                // Tail byte-wise comparison
                while (ip + mlen < iend && ref[mlen] == ip[mlen])
                    mlen++;

            _match_len_done:

                if (mlen > best_len)
                {
                    best_len = mlen;
                    best_ref = ref;
                    if (best_len >= 128)
                        break;
                }
            }
            match_idx = ctx->chain_table[match_idx];
        }

        if (use_lazy && best_ref && best_len < 128 && ip + 1 < mflimit)
        {
            uint32_t next_val = zxc_le32(ip + 1);
            uint32_t h2 = (next_val * 2654435761U) >> (32 - ZXC_LZ_HASH_BITS);
            uint32_t next_head = ctx->hash_table[2 * h2];
            uint32_t next_idx =
                (next_head & ~ZXC_OFFSET_MASK) == epoch_mark ? (next_head & ZXC_OFFSET_MASK) : 0;

            uint32_t max_lazy = 0;
            int lazy_att = 8;
            while (next_idx > 0 && lazy_att-- > 0)
            {
                if ((uint32_t)(ip + 1 - src) - next_idx >= ZXC_LZ_MAX_DIST)
                    break;
                const uint8_t *ref2 = src + next_idx;
                if (zxc_le32(ref2) == next_val)
                {
                    uint32_t l2 = 4;
                    while (ip + 1 + l2 < iend && ref2[l2] == ip[1 + l2])
                        l2++;
                    if (l2 > max_lazy)
                        max_lazy = l2;
                }
                next_idx = ctx->chain_table[next_idx];
            }

            if (max_lazy > best_len + 1)
            {
                best_ref = NULL;
            }
        }

        if (best_ref)
        {
            // Match found. Backward scan to find start of match.
            while (ip > anchor && best_ref > src && ip[-1] == best_ref[-1])
            {
                ip--;
                best_ref--;
                best_len++;
            }

            ctx->sequences[seq_c].lit_len = (uint32_t)(ip - anchor);
            ctx->sequences[seq_c].match_len = (uint32_t)(best_len - ZXC_LZ_MIN_MATCH);
            ctx->sequences[seq_c].offset = (uint32_t)(ip - best_ref);

            if (ctx->sequences[seq_c].lit_len > 0)
            {
                memcpy(ctx->literals + lit_c, anchor, ctx->sequences[seq_c].lit_len);
                lit_c += ctx->sequences[seq_c].lit_len;
            }
            seq_c++;

            ip += best_len;
            anchor = ip;
        }
        else
        {
            ip += step;
        }
    }

    size_t last_lits = iend - anchor;
    if (last_lits > 0)
    {
        memcpy(ctx->literals + lit_c, anchor, last_lits);
        lit_c += last_lits;
    }

    uint32_t max_ll = 0, max_ml = 0, max_off = 0;
    for (uint32_t i = 0; i < seq_c; i++)
    {
        ctx->buf_ll[i] = ctx->sequences[i].lit_len;
        if (ctx->buf_ll[i] > max_ll)
            max_ll = ctx->buf_ll[i];
        ctx->buf_ml[i] = ctx->sequences[i].match_len;
        if (ctx->buf_ml[i] > max_ml)
            max_ml = ctx->buf_ml[i];
        ctx->buf_off[i] = ctx->sequences[i].offset;
        if (ctx->buf_off[i] > max_off)
            max_off = ctx->buf_off[i];
    }

    size_t h_gap = ZXC_BLOCK_HEADER_SIZE + (chk ? 4 : 0);
    zxc_block_header_t bh = {.block_type = ZXC_BLOCK_GNR, .raw_size = (uint32_t)src_size};
    uint8_t *p = dst + h_gap;
    size_t rem = dst_cap - h_gap;
    uint8_t b_ll = zxc_highbit32(max_ll), b_ml = zxc_highbit32(max_ml),
            b_off = zxc_highbit32(max_off);
    zxc_gnr_header_t gh = {.n_sequences = seq_c,
                           .n_literals = (uint32_t)lit_c,
                           .enc_lit = ZXC_SECTION_ENCODING_RAW,
                           .enc_litlen = b_ll,
                           .enc_mlen = b_ml,
                           .enc_off = b_off};

    if (lit_c > 0 && zxc_is_rle(ctx->literals, lit_c))
        gh.enc_lit = ZXC_SECTION_ENCODING_RLE;
    zxc_section_desc_t desc[4] = {0};
    int ghs = zxc_write_gnr_header_and_desc(p, rem, &gh, desc);
    if (UNLIKELY(ghs < 0))
        return -1;

    uint8_t *p_curr = p + ghs;
    rem -= ghs;

    if (gh.enc_lit == ZXC_SECTION_ENCODING_RLE)
    {
        *p_curr++ = ctx->literals[0];
        desc[0].comp_size = 1;
    }
    else
    {
        memcpy(p_curr, ctx->literals, lit_c);
        p_curr += lit_c;
        desc[0].comp_size = (uint32_t)lit_c;
    }

    desc[0].raw_size = (uint32_t)lit_c;
    rem -= desc[0].comp_size;

    desc[1].comp_size = zxc_bitpack_stream_32(ctx->buf_ll, seq_c, p_curr, rem, b_ll);
    p_curr += desc[1].comp_size;
    rem -= desc[1].comp_size;

    desc[2].comp_size = zxc_bitpack_stream_32(ctx->buf_ml, seq_c, p_curr, rem, b_ml);
    p_curr += desc[2].comp_size;
    rem -= desc[2].comp_size;

    desc[3].comp_size = zxc_bitpack_stream_32(ctx->buf_off, seq_c, p_curr, rem, b_off);
    p_curr += desc[3].comp_size;
    rem -= desc[3].comp_size;

    zxc_write_gnr_header_and_desc(p, dst_cap - h_gap, &gh, desc);
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
 * This function prepares and writes a "RAW" type block into the destination buffer.
 * It handles the block header, copying of source data, and optionally
 * the calculation and storage of a checksum.
 *
 * @param src Pointer to the source data to encode.
 * @param sz Size of the source data in bytes.
 * @param dst Pointer to the destination buffer.
 * @param cap Maximum capacity of the destination buffer.
 * @param out_sz Pointer to a variable receiving the total written size (header + data + checksum).
 * @param chk Boolean flag: if non-zero, a checksum is calculated and added.
 * @param p_crc Pointer to store or retrieve the calculated CRC value (used if chk is active).
 *
 * @return 0 on success, -1 if the destination buffer capacity is insufficient.
 */
static int zxc_encode_block_raw(const uint8_t *src, size_t sz, uint8_t *dst, size_t cap,
                                size_t *out_sz, int chk, uint32_t *p_crc)
{
    size_t h_gap = ZXC_BLOCK_HEADER_SIZE + (chk ? 4 : 0);
    if (UNLIKELY(cap < h_gap + sz))
        return -1;
    zxc_block_header_t bh = {.block_type = ZXC_BLOCK_RAW, .raw_size = (uint32_t)sz};

    if (chk)
    {
        if (p_crc)
            *p_crc = zxc_copy_and_checksum(src, dst + h_gap, sz, 0);
        bh.block_flags |= ZXC_BLOCK_FLAG_CHECKSUM;
    }
    else
    {
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
 * entropy is above a certain threshold, the block is skipped to save processing time.
 *
 * @note This is an estimation and not a precise entropy calculation.
 *
 * @param[in] data Pointer to the input data buffer.
 * @param[in] size Size of the input data in bytes.
 * @return A heuristic score indicating compressibility (lower means more compressible).
 */
// Quick 0-order Entropy Heuristic to skip incompressible blocks (e.g., encrypted data)
static int zxc_check_compressibility(const uint8_t *src, size_t src_size)
{
    size_t step = 32;
    if (src_size < 2048)
        step = 1;
    else if (src_size < 8192)
        step = 8;

    uint32_t counts[256] = {0};
    size_t total_samples = 0;

    const uint8_t *p = src;
    const uint8_t *end = src + src_size;

    while (p < end)
    {
        counts[*p]++;
        p += step;
        total_samples++;
    }

    // Calculate sum of squares to estimate distribution uniformity
    uint64_t sum_sq = 0;
    for (int i = 0; i < 256; i++)
    {
        if (counts[i] > 0)
            sum_sq += (uint64_t)counts[i] * counts[i];
    }

    uint64_t threshold = (total_samples * total_samples) / 180;

    return (sum_sq > threshold);
}

/**
 * @brief Wraps the compression logic for a single chunk of data, selecting the best encoding
 * strategy.
 *
 * This function attempts to compress a given data chunk using different strategies based on
 * the data size and compressibility. It handles the decision-making process between raw encoding,
 * general-purpose compression (GNR), and numerical compression (NUM).
 *
 * The logic flow is as follows:
 * 1. If the chunk size is large (>= 1024 bytes) and deemed incompressible by a heuristic check,
 *    it defaults immediately to raw encoding.
 * 2. Otherwise, it attempts general-purpose compression (GNR).
 * 3. If GNR fails or results in a poor compression ratio (> 90%) for specific block sizes,
 *    it attempts numerical compression (NUM).
 * 4. If numerical compression is successful and efficient, it is used.
 * 5. If all compression attempts fail or are inefficient, it falls back to raw encoding.
 *
 * @param ctx Pointer to the ZXC compression context containing configuration (e.g., checksum
 * flags).
 * @param chunk Pointer to the source data buffer to be compressed.
 * @param sz Size of the source data chunk in bytes.
 * @param dst Pointer to the destination buffer where compressed data will be written.
 * @param cap Capacity of the destination buffer.
 *
 * @return The size of the written data in bytes on success, or -1 if an error occurred
 *         (e.g., buffer overflow or encoding failure).
 */
static int zxc_compress_chunk_wrapper(zxc_cctx_t *ctx, const uint8_t *chunk, size_t sz,
                                      uint8_t *dst, size_t cap)
{
    int chk = ctx->checksum_enabled;

    if (sz >= 1024)
    {
        if (!zxc_check_compressibility(chunk, sz))
        {
            size_t w_raw = 0;
            uint32_t crc = 0;
            if (zxc_encode_block_raw(chunk, sz, dst, cap, &w_raw, chk, &crc) != 0)
                return -1;
            return (int)w_raw;
        }
    }

    size_t w = 0;
    uint32_t crc = 0;
    int r_gnr = zxc_encode_block_gnr(ctx, chunk, sz, dst, cap, &w, chk, &crc);
    int try_num = (r_gnr != 0) || ((double)w / (double)sz > 0.90 && sz > 128 && sz % 4 == 0);
    if (try_num)
    {
        size_t wn = 0;
        if (zxc_encode_block_num(chunk, sz, dst, cap, &wn, chk, &crc) == 0 &&
            wn <= sz + ZXC_BLOCK_HEADER_SIZE + 4)
            return (int)wn;
        uint32_t *p_raw_crc = &crc;
        if (zxc_encode_block_raw(chunk, sz, dst, cap, &w, chk, p_raw_crc) != 0)
            return -1;
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
 * @param f_out     Pointer to the output file stream where compressed data will be written.
 * @param n_threads The number of threads to use for parallel compression.
 * @param level     The compression level (determines the trade-off between speed and ratio).
 * @param checksum  Flag indicating whether to calculate and store a checksum for data integrity.
 *
 * @return          Returns 0 on success, or a non-zero error code on failure.
 */
int zxc_stream_compress(FILE *f_in, FILE *f_out, int n_threads, zxc_level_t level, int checksum)
{
    return zxc_stream_engine_run(f_in, f_out, n_threads, 1, level, checksum,
                                 zxc_compress_chunk_wrapper);
}
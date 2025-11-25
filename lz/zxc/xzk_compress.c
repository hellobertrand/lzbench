#include "xzk_internal.h"
#include "xzk.h"

#define XZK_NUM_FRAME_SIZE 128

static int xzk_encode_block_num(const uint8_t *src, size_t src_size, uint8_t *dst, size_t dst_cap, size_t *out_sz, int chk, uint32_t *p_crc)
{
    if (src_size % 4 != 0 || src_size == 0)
        return -1;
    if (chk && p_crc)
        *p_crc = xzk_xxh32(src, src_size, 0);
    size_t count = src_size / 4;
    size_t h_gap = XZK_BLOCK_HEADER_SIZE + (chk ? 4 : 0);
    if (UNLIKELY(dst_cap < h_gap + XZK_NUM_HEADER_BINARY_SIZE))
        return -1;
    xzk_block_header_t bh = {.block_type = XZK_BLOCK_NUM, .raw_size = (uint32_t)src_size};
    uint8_t *p_curr = dst + h_gap;
    size_t rem = dst_cap - h_gap;
    xzk_num_header_t nh = {.n_values = count, .frame_size = XZK_NUM_FRAME_SIZE};
    int hs = xzk_write_num_header(p_curr, rem, &nh);
    if (UNLIKELY(hs < 0))
        return -1;
    p_curr += hs;
    rem -= hs;
    uint32_t deltas[XZK_NUM_FRAME_SIZE];
    const uint8_t *in_ptr = src;
    uint32_t prev = 0;
    for (size_t i = 0; i < count; i += XZK_NUM_FRAME_SIZE)
    {
        size_t frames = (count - i < XZK_NUM_FRAME_SIZE) ? (count - i) : XZK_NUM_FRAME_SIZE;
        uint32_t max_d = 0, base = prev;
        size_t j = 0;
#if defined(XZK_USE_AVX2)
        if (frames >= 8)
        {
            for (; j < (frames & ~7); j += 8)
            {
                if (i == 0 && j == 0)
                    goto _scalar;
                __m256i vc = _mm256_loadu_si256((const __m256i *)(in_ptr + j * 4));
                __m256i vp = _mm256_loadu_si256((const __m256i *)(in_ptr + j * 4 - 4));
                __m256i diff = _mm256_sub_epi32(vc, vp);
                _mm256_storeu_si256((__m256i *)&deltas[j], _mm256_xor_si256(_mm256_slli_epi32(diff, 1), _mm256_srai_epi32(diff, 31)));
            }
        }
#endif
    _scalar:
#ifndef _MSC_VER
        __attribute__((unused));
#endif
        for (; j < frames; j++)
        {
            uint32_t v = xzk_le32(in_ptr + j * 4);
            deltas[j] = xzk_zigzag_encode((int32_t)(v - prev));
            prev = v;
        }
        for (size_t k = 0; k < frames; k++)
            if (deltas[k] > max_d)
                max_d = deltas[k];
        if (frames > 0)
            prev = xzk_le32(in_ptr + (frames - 1) * 4);
        in_ptr += frames * 4;
        uint8_t bits = xzk_highbit32(max_d);
        size_t packed = ((frames * bits) + 7) / 8;
        if (UNLIKELY(rem < 16 + packed))
            return -1;
        xzk_store_le16(p_curr, (uint16_t)frames);
        xzk_store_le16(p_curr + 2, bits);
        xzk_store_le64(p_curr + 4, (uint64_t)base);
        xzk_store_le32(p_curr + 12, (uint32_t)packed);
        p_curr += 16;
        rem -= 16;
        int pb = xzk_bitpack_stream_32(deltas, frames, p_curr, rem, bits);
        if (UNLIKELY(pb < 0))
            return -1;
        p_curr += pb;
        rem -= pb;
    }
    uint32_t p_sz = (uint32_t)(p_curr - (dst + h_gap));
    int hw = xzk_write_block_header(dst, dst_cap, &bh);
    if (chk)
        bh.block_flags |= XZK_BLOCK_FLAG_CHECKSUM;
    else
        bh.block_flags &= ~XZK_BLOCK_FLAG_CHECKSUM;
    bh.comp_size = p_sz;
    hw = xzk_write_block_header(dst, dst_cap, &bh);
    if (chk)
        xzk_store_le32(dst + hw, *p_crc);
    *out_sz = hw + (chk ? 4 : 0) + p_sz;
    return 0;
}

static int xzk_encode_block_gnr(xzk_cctx_t *ctx, const uint8_t *src, size_t src_size, uint8_t *dst, size_t dst_cap, size_t *out_sz, int chk, uint32_t *p_crc)
{
    memset(ctx->hash_table, 0, 2 * XZK_LZ_HASH_SIZE * sizeof(uint32_t));
    const uint8_t *ip = src, *iend = src + src_size, *anchor = ip, *mflimit = iend - 12;
    uint32_t seq_c = 0;
    size_t lit_c = 0;
    uint32_t crc_calc = 0;
    if (chk)
        crc_calc = xzk_xxh32(src, src_size, 0);
    if (p_crc)
        *p_crc = crc_calc;

    while (LIKELY(ip < mflimit))
    {
        XZK_PREFETCH_READ(ip + 128);
        uint32_t h = (xzk_le32(ip) * 2654435761U) >> (32 - XZK_LZ_HASH_BITS);
        uint32_t idx0 = ctx->hash_table[2 * h], idx1 = ctx->hash_table[2 * h + 1];
        ctx->hash_table[2 * h + 1] = idx0;
        ctx->hash_table[2 * h] = (uint32_t)(ip - src);
        const uint8_t *ref0 = src + idx0, *ref1 = src + idx1;
        uint32_t cur_val = xzk_le32(ip);
        int match0 = (idx0 < (uint32_t)(ip - src) && (uint32_t)(ip - src) - idx0 < XZK_LZ_MAX_DIST && xzk_le32(ref0) == cur_val);
        int match1 = (idx1 < (uint32_t)(ip - src) && (uint32_t)(ip - src) - idx1 < XZK_LZ_MAX_DIST && xzk_le32(ref1) == cur_val);
        const uint8_t *best_ref = NULL;
        if (match0)
        {
            best_ref = ref0;
            if (match1)
            {
                uint32_t len0 = 4;
                while (ip + len0 < mflimit && ref0[len0] == ip[len0])
                    len0++;
                uint32_t len1 = 4;
                while (ip + len1 < mflimit && ref1[len1] == ip[len1])
                    len1++;
                if (len1 > len0)
                    best_ref = ref1;
            }
        }
        else if (match1)
        {
            best_ref = ref1;
        }
        if (best_ref)
        {
            uint32_t mlen = 4;
            const uint8_t *limit_8 = iend - 8;
            while (ip + mlen < limit_8 && best_ref[mlen] == ip[mlen])
            {
                if (xzk_le64(best_ref + mlen) == xzk_le64(ip + mlen))
                    mlen += 8;
                else
                {
                    while (ip + mlen < iend && best_ref[mlen] == ip[mlen])
                        mlen++;
                    break;
                }
            }
            while (ip + mlen < iend && best_ref[mlen] == ip[mlen])
                mlen++;
            ctx->sequences[seq_c].lit_len = (uint32_t)(ip - anchor);
            ctx->sequences[seq_c].match_len = (uint32_t)(mlen - XZK_LZ_MIN_MATCH);
            ctx->sequences[seq_c].offset = (uint32_t)(ip - best_ref);
            if (ctx->sequences[seq_c].lit_len > 0)
            {
                memcpy(ctx->literals + lit_c, anchor, ctx->sequences[seq_c].lit_len);
                lit_c += ctx->sequences[seq_c].lit_len;
            }
            seq_c++;
            ip += mlen;
            anchor = ip;
            if (LIKELY(ip < mflimit))
            {
                uint32_t h2 = (xzk_le32(ip - 2) * 2654435761U) >> (32 - XZK_LZ_HASH_BITS);
                ctx->hash_table[2 * h2 + 1] = ctx->hash_table[2 * h2];
                ctx->hash_table[2 * h2] = (uint32_t)(ip - 2 - src);
            }
        }
        else
        {
            ip++;
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
    size_t h_gap = XZK_BLOCK_HEADER_SIZE + (chk ? 4 : 0);
    xzk_block_header_t bh = {.block_type = XZK_BLOCK_GNR, .raw_size = (uint32_t)src_size};
    uint8_t *p = dst + h_gap;
    size_t rem = dst_cap - h_gap;
    uint8_t b_ll = xzk_highbit32(max_ll), b_ml = xzk_highbit32(max_ml), b_off = xzk_highbit32(max_off);
    xzk_gnr_header_t gh = {.n_sequences = seq_c, .n_literals = (uint32_t)lit_c, .enc_lit = XZK_SECTION_ENCODING_RAW, .enc_litlen = b_ll, .enc_mlen = b_ml, .enc_off = b_off};
    if (lit_c > 0 && xzk_is_rle(ctx->literals, lit_c))
        gh.enc_lit = XZK_SECTION_ENCODING_RLE;
    xzk_section_desc_t desc[4] = {0};
    int ghs = xzk_write_gnr_header_and_desc(p, rem, &gh, desc);
    if (UNLIKELY(ghs < 0))
        return -1;
    uint8_t *p_curr = p + ghs;
    rem -= ghs;
    if (gh.enc_lit == XZK_SECTION_ENCODING_RLE)
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
    desc[1].comp_size = xzk_bitpack_stream_32(ctx->buf_ll, seq_c, p_curr, rem, b_ll);
    p_curr += desc[1].comp_size;
    rem -= desc[1].comp_size;
    desc[2].comp_size = xzk_bitpack_stream_32(ctx->buf_ml, seq_c, p_curr, rem, b_ml);
    p_curr += desc[2].comp_size;
    rem -= desc[2].comp_size;
    desc[3].comp_size = xzk_bitpack_stream_32(ctx->buf_off, seq_c, p_curr, rem, b_off);
    p_curr += desc[3].comp_size;
    rem -= desc[3].comp_size;
    xzk_write_gnr_header_and_desc(p, dst_cap - h_gap, &gh, desc);
    uint32_t p_sz = (uint32_t)(p_curr - (dst + h_gap));
    if (chk)
        bh.block_flags |= XZK_BLOCK_FLAG_CHECKSUM;
    else
        bh.block_flags &= ~XZK_BLOCK_FLAG_CHECKSUM;
    bh.comp_size = p_sz;
    int wh = xzk_write_block_header(dst, dst_cap, &bh);
    if (chk)
        xzk_store_le32(dst + wh, *p_crc);
    *out_sz = wh + (chk ? 4 : 0) + p_sz;
    return 0;
}

static int xzk_encode_block_raw(const uint8_t *src, size_t sz, uint8_t *dst, size_t cap, size_t *out_sz, int chk, uint32_t *p_crc)
{
    size_t h_gap = XZK_BLOCK_HEADER_SIZE + (chk ? 4 : 0);
    if (UNLIKELY(cap < h_gap + sz))
        return -1;
    xzk_block_header_t bh = {.block_type = XZK_BLOCK_RAW, .raw_size = (uint32_t)sz};
    if (chk && p_crc)
        *p_crc = xzk_copy_and_checksum(src, dst + h_gap, sz, 0);
    else
        memcpy(dst + h_gap, src, sz);
    if (chk)
        bh.block_flags |= XZK_BLOCK_FLAG_CHECKSUM;
    else
        bh.block_flags &= ~XZK_BLOCK_FLAG_CHECKSUM;
    bh.comp_size = (uint32_t)sz;
    int wh = xzk_write_block_header(dst, cap, &bh);
    if (chk)
        xzk_store_le32(dst + wh, *p_crc);
    *out_sz = wh + (chk ? 4 : 0) + sz;
    return 0;
}

static int compress_chunk_wrapper(xzk_cctx_t *ctx, const uint8_t *chunk, size_t sz, uint8_t *dst, size_t cap)
{
    int chk = XZK_DEFAULT_CHECKSUM_ENABLED;
    if (sz >= 8192)
    {
        uint8_t tmp_dst[4096 + 512];
        size_t sample_sz = 4096;
        size_t test_out_sz = 0;
        uint32_t dummy_crc;
        int r_test = xzk_encode_block_gnr(ctx, chunk, sample_sz, tmp_dst, sizeof(tmp_dst), &test_out_sz, 0, &dummy_crc);
        if (r_test == 0 && test_out_sz > 4014)
        {
            size_t w_raw = 0;
            uint32_t crc = 0;
            if (xzk_encode_block_raw(chunk, sz, dst, cap, &w_raw, chk, &crc) != 0)
                return -1;
            return (int)w_raw;
        }
    }
    size_t w = 0;
    uint32_t crc = 0;
    int r_gnr = xzk_encode_block_gnr(ctx, chunk, sz, dst, cap, &w, chk, &crc);
    int try_num = (r_gnr != 0) || ((double)w / (double)sz > 0.90 && sz > 128 && sz % 4 == 0);
    if (try_num)
    {
        size_t wn = 0;
        if (xzk_encode_block_num(chunk, sz, dst, cap, &wn, chk, &crc) == 0 && wn <= sz + XZK_BLOCK_HEADER_SIZE + 4)
            return (int)wn;
        uint32_t *p_raw_crc = (r_gnr == 0) ? &crc : NULL;
        if (xzk_encode_block_raw(chunk, sz, dst, cap, &w, chk, p_raw_crc) != 0)
            return -1;
    }
    return (int)w;
}

int xzk_stream_compress(FILE *f_in, FILE *f_out, int n_threads)
{
    return xzk_stream_engine_run(f_in, f_out, n_threads, 1, compress_chunk_wrapper);
}
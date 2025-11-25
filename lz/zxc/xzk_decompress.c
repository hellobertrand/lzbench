#include "xzk_internal.h"
#include "xzk.h"

// --- Fonctions d'Optimisation Locales (Remplacement des Macros) ---

// Force l'inlining pour garantir la performance
#if defined(__GNUC__) || defined(__clang__)
#define XZK_ALWAYS_INLINE inline __attribute__((always_inline))
#elif defined(_MSC_VER)
#define XZK_ALWAYS_INLINE __forceinline
#else
#define XZK_ALWAYS_INLINE inline
#endif

static XZK_ALWAYS_INLINE uint32_t xzk_br_consume_fast(xzk_bit_reader_t *br, uint8_t n)
{
    // Utilisation de 1ULL pour éviter l'overflow si n=32 sur certains systèmes
    uint32_t val = (uint32_t)(br->accum & ((1ULL << n) - 1));
    br->accum >>= n;
    br->bits -= n;
    return val;
}

static XZK_ALWAYS_INLINE void xzk_br_ensure(xzk_bit_reader_t *br, int needed)
{
    if (UNLIKELY(br->bits < needed))
    {
        // PROTECTION 1 : Si on a "trop consommé" (bits < 0) à cause d'une fin de fichier,
        // on remet à zéro pour éviter des shifts négatifs (Undefined Behavior).
        int safe_bits = (br->bits < 0) ? 0 : br->bits;
        br->bits = safe_bits;

        // PROTECTION 2 : Nettoyage des bits supérieurs poubelles
        // On utilise 1ULL pour la sécurité 64 bits
        br->accum &= ((1ULL << safe_bits) - 1);

        const uint8_t *p_loc = br->ptr;
        const uint8_t *e_loc = br->end;

        // Fast Path : On charge 64 bits d'un coup si possible
        if (LIKELY(p_loc + 8 <= e_loc))
        {
            uint64_t raw = xzk_le64(p_loc);
            int consumed = (64 - safe_bits) >> 3;
            br->accum |= (raw << safe_bits);
            p_loc += consumed;
            br->bits = safe_bits + consumed * 8;
        }
        else
        {
            // Slow Path : Fin de fichier, octet par octet
            while (p_loc < e_loc && br->bits <= 56)
            {
                br->accum |= ((uint64_t)(*p_loc++)) << br->bits;
                br->bits += 8;
            }
        }
        br->ptr = p_loc;
    }
}

static int xzk_decode_block_num(const uint8_t *restrict src, size_t src_size, uint8_t *restrict dst, size_t dst_capacity, uint32_t expected_raw_size)
{
    (void)expected_raw_size;

    xzk_num_header_t nh;
    if (UNLIKELY(xzk_read_num_header(src, src_size, &nh) != 0))
        return -1;
    const uint8_t *p = src + XZK_NUM_HEADER_BINARY_SIZE;
    const uint8_t *p_end = src + src_size;
    uint8_t *d_ptr = dst;
    uint8_t *d_end = dst + dst_capacity;
    uint64_t vals_remaining = nh.n_values;
    uint32_t running_val = 0;

    while (vals_remaining > 0)
    {
        if (UNLIKELY(p + 16 > p_end))
            return -1;
        uint16_t nvals = xzk_le16(p + 0);
        uint16_t bits = xzk_le16(p + 2);
        uint32_t psize = xzk_le32(p + 12);
        p += 16;

        if (UNLIKELY(p + psize > p_end || d_ptr + nvals * 4 > d_end))
            return -1;

        xzk_bit_reader_t br;
        xzk_br_init(&br, p, psize);

        uint32_t i = 0;

        // OPTIMISATION : Boucle déroulée + Branchless Bit Reader
        // On traite 4 valeurs par itération
        for (; i + 4 <= nvals; i += 4)
        {
            // On s'assure d'avoir assez de bits pour décoder 4 valeurs d'un coup
            // (4 * bits). Si 'bits' est grand (ex: 32), on devra recharger plus souvent.
            // Pour la simplicité et la sécurité, on recharge avant chaque consommation
            // si nécessaire, mais avec la version rapide inline.

            // Valeur 1
            xzk_br_ensure(&br, bits);
            uint32_t r1 = xzk_br_consume_fast(&br, bits);
            running_val += xzk_zigzag_decode(r1);
            xzk_store_le32(d_ptr, running_val);
            d_ptr += 4;

            // Valeur 2
            xzk_br_ensure(&br, bits);
            uint32_t r2 = xzk_br_consume_fast(&br, bits);
            running_val += xzk_zigzag_decode(r2);
            xzk_store_le32(d_ptr, running_val);
            d_ptr += 4;

            // Valeur 3
            xzk_br_ensure(&br, bits);
            uint32_t r3 = xzk_br_consume_fast(&br, bits);
            running_val += xzk_zigzag_decode(r3);
            xzk_store_le32(d_ptr, running_val);
            d_ptr += 4;

            // Valeur 4
            xzk_br_ensure(&br, bits);
            uint32_t r4 = xzk_br_consume_fast(&br, bits);
            running_val += xzk_zigzag_decode(r4);
            xzk_store_le32(d_ptr, running_val);
            d_ptr += 4;
        }

        // Finition
        for (; i < nvals; i++)
        {
            xzk_br_ensure(&br, bits);
            uint32_t r = xzk_br_consume_fast(&br, bits);
            running_val += xzk_zigzag_decode(r);
            xzk_store_le32(d_ptr, running_val);
            d_ptr += 4;
        }

        p += psize;
        vals_remaining -= nvals;
    }
    return (int)(d_ptr - dst);
}

static int xzk_decode_block_gnr(const uint8_t *restrict src, size_t src_size, uint8_t *restrict dst, size_t dst_capacity, uint32_t expected_raw_size)
{
    xzk_gnr_header_t gh;
    xzk_section_desc_t desc[4];
    if (UNLIKELY(xzk_read_gnr_header_and_desc(src, src_size, &gh, desc) != 0))
        return -1;

    const uint8_t *p_data = src + XZK_GNR_HEADER_BINARY_SIZE + 4 * XZK_SECTION_DESC_BINARY_SIZE;
    const uint8_t *ptr_lit = p_data;
    const uint8_t *ptr_ll = ptr_lit + desc[0].comp_size;
    const uint8_t *ptr_ml = ptr_ll + desc[1].comp_size;
    const uint8_t *ptr_off = ptr_ml + desc[2].comp_size;

    xzk_bit_reader_t br_ll, br_ml, br_off;
    xzk_br_init(&br_ll, ptr_ll, desc[1].comp_size);
    xzk_br_init(&br_ml, ptr_ml, desc[2].comp_size);
    xzk_br_init(&br_off, ptr_off, desc[3].comp_size);

    uint8_t *d_ptr = dst;
    uint8_t *d_end = dst + dst_capacity;
    uint8_t *d_end_safe = d_end - 32;
    const uint8_t *l_ptr = ptr_lit;

    int is_rle = (gh.enc_lit == XZK_SECTION_ENCODING_RLE);
    uint8_t rle_char = is_rle ? ptr_lit[0] : 0;

    const uint8_t b_ll = gh.enc_litlen;
    const uint8_t b_ml = gh.enc_mlen;
    const uint8_t b_off = gh.enc_off;

    uint32_t n_seq = gh.n_sequences;

    while (n_seq--)
    {
        // Lecture LL
        xzk_br_ensure(&br_ll, b_ll);
        uint32_t ll = xzk_br_consume_fast(&br_ll, b_ll);

        // Lecture ML
        xzk_br_ensure(&br_ml, b_ml);
        uint32_t ml = xzk_br_consume_fast(&br_ml, b_ml) + XZK_LZ_MIN_MATCH;

        // Lecture Offset
        xzk_br_ensure(&br_off, b_off);
        uint32_t off = xzk_br_consume_fast(&br_off, b_off);

        XZK_PREFETCH_READ(l_ptr + 64);
        // XZK_PREFETCH_WRITE(d_ptr + 128);
        if (LIKELY(d_ptr + ll + ml < d_end_safe))
        {
            if (is_rle)
            {
                memset(d_ptr, rle_char, ll);
                d_ptr += ll;
            }
            else
            {
                // Wild Copy: On copie par blocs de 16 octets tant qu'on n'a pas atteint la fin.
                // On dépasse potentiellement la fin de 'll', mais ce n'est pas grave car
                // la zone mémoire suivante sera écrasée par la copie "Match" juste après.
                const uint8_t *src_lit = l_ptr;
                uint8_t *dst_lit = d_ptr;
                uint8_t *target_lit_end = d_ptr + ll;

                // Astuce : Une boucle do-while simple.
                // Le compilateur va transformer ce memcpy constant en instruction vectorielle (MOVUPS/LDP).
                do
                {
                    memcpy(dst_lit, src_lit, 16);
                    dst_lit += 16;
                    src_lit += 16;
                } while (dst_lit < target_lit_end);

                d_ptr += ll;
                l_ptr += ll;
            }

            uint8_t *match_src = d_ptr - off;

            if (off >= 16)
            {
                uint8_t *out = d_ptr;
                uint8_t *target_match_end = d_ptr + ml;
                do
                {
                    memcpy(out, match_src, 16);
                    out += 16;
                    match_src += 16;
                } while (out < target_match_end);
                d_ptr += ml;
            }
            else
            {
                // Offset court (< 16) : Risque de corruption si on utilise memcpy 16.
                // On garde la boucle classique octet par octet pour l'instant.
                // (C'est le prochain point d'optimisation si nécessaire)
                // for (size_t i = 0; i < ml; i++)
                //     d_ptr[i] = match_src[i];
                // d_ptr += ml;

                // OPTIMISATION SHORT OFFSET(Overlap Hazard)

                // Cas 1 : RLE (Offset == 1)
                // Très fréquent. La source est constante (le caractère précédent).
                // memset est généralement optimisé en SIMD par la libc/compilateur.
                if (off == 1)
                {
                    memset(d_ptr, match_src[0], ml);
                    d_ptr += ml;
                }
                else
                {
                    // Cas 2 : Petit chevauchement (2 <= off < 16)
                    // On ne peut pas utiliser memcpy/SIMD car src dépend de dst fraîchement écrit.
                    // Mais on peut dérouler la boucle pour réduire l'overhead CPU (branch prediction).

                    uint8_t *end = d_ptr + ml;

                    // Déroulage par 4 octets (suffisant pour saturer les ports ALU scalaires)
                    // Note: Comme LZ_MIN_MATCH = 4, on rentre presque toujours ici.
                    while (d_ptr + 4 <= end)
                    {
                        d_ptr[0] = match_src[0];
                        d_ptr[1] = match_src[1];
                        d_ptr[2] = match_src[2];
                        d_ptr[3] = match_src[3];
                        d_ptr += 4;
                        match_src += 4;
                    }

                    // Finition (0 à 3 octets restants)
                    while (d_ptr < end)
                    {
                        *d_ptr++ = *match_src++;
                    }
                }
            }
        }
        else
        {
            if (UNLIKELY(d_ptr + ll > d_end))
                return -1;
            if (is_rle)
                memset(d_ptr, rle_char, ll);
            else
            {
                memcpy(d_ptr, l_ptr, ll);
                l_ptr += ll;
            }
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
    if (generated < expected_raw_size)
    {
        size_t rem = expected_raw_size - generated;
        if (UNLIKELY(d_ptr + rem > d_end))
            return -1;
        if (is_rle)
            memset(d_ptr, rle_char, rem);
        else
            memcpy(d_ptr, l_ptr, rem);
        d_ptr += rem;
    }
    return (int)(d_ptr - dst);
}

static int decompress_chunk_wrapper(xzk_cctx_t *ctx, const uint8_t *src, size_t src_sz, uint8_t *dst, size_t dst_cap)
{
    (void)ctx; // Unused for decompress
    xzk_block_header_t bh;
    if (xzk_read_block_header(src, src_sz, &bh) != 0)
        return -1;
    int has_crc = (bh.block_flags & XZK_BLOCK_FLAG_CHECKSUM);
    size_t over = XZK_BLOCK_HEADER_SIZE + (has_crc ? 4 : 0);
    const uint8_t *data = src + over;
    if (bh.block_type == XZK_BLOCK_RAW)
    {
        if (bh.raw_size > dst_cap)
            return -1;
        memcpy(dst, data, bh.raw_size);
        return bh.raw_size;
    }
    if (bh.block_type == XZK_BLOCK_NUM)
        return xzk_decode_block_num(data, bh.comp_size, dst, dst_cap, bh.raw_size);
    if (bh.block_type == XZK_BLOCK_GNR)
        return xzk_decode_block_gnr(data, bh.comp_size, dst, dst_cap, bh.raw_size);
    return -1;
}

int xzk_stream_decompress(FILE *f_in, FILE *f_out, int n_threads)
{
    return xzk_stream_engine_run(f_in, f_out, n_threads, 0, decompress_chunk_wrapper);
}

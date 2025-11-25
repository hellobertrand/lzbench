#include "xzk_internal.h"
#include "xzk.h"

/* --- MODIFICATION WINDOWS START --- */
#ifdef _WIN32
#include <windows.h>
#include <process.h>
#include <sys/types.h>

// Emulation basique de sysconf pour _SC_NPROCESSORS_ONLN
static int xzk_get_num_procs(void)
{
    SYSTEM_INFO sysinfo;
    GetSystemInfo(&sysinfo);
    return sysinfo.dwNumberOfProcessors;
}

// Mapping Pthread -> Windows CriticalSection / ConditionVariable
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

typedef struct
{
    void *(*func)(void *);
    void *arg;
} xzk_win_thread_arg_t;

static unsigned __stdcall xzk_win_thread_entry(void *p)
{
    xzk_win_thread_arg_t *a = (xzk_win_thread_arg_t *)p;
    void *(*f)(void *) = a->func;
    void *arg = a->arg;
    free(a);
    f(arg);
    return 0;
}

static int pthread_create(pthread_t *thread, const void *attr, void *(*start_routine)(void *), void *arg)
{
    xzk_win_thread_arg_t *wrapper = malloc(sizeof(xzk_win_thread_arg_t));
    if (!wrapper)
        return -1;
    wrapper->func = start_routine;
    wrapper->arg = arg;
    uintptr_t handle = _beginthreadex(NULL, 0, xzk_win_thread_entry, wrapper, 0, NULL);
    if (handle == 0)
    {
        free(wrapper);
        return -1;
    }
    *thread = (HANDLE)handle;
    return 0;
}

static int pthread_join(pthread_t thread, void **retval)
{
    WaitForSingleObject(thread, INFINITE);
    CloseHandle(thread);
    return 0;
}

#define sysconf(x) xzk_get_num_procs()
#define _SC_NPROCESSORS_ONLN 0

#else
#include <pthread.h>
#include <unistd.h>
#endif
/* --- MODIFICATION WINDOWS END --- */

// --- Gestion Contextes ---
int xzk_cctx_init(xzk_cctx_t *ctx, size_t chunk_size)
{
    size_t max_seq = chunk_size / 4 + 256;
    ctx->hash_table = malloc(2 * XZK_LZ_HASH_SIZE * sizeof(uint32_t));
    ctx->sequences = malloc(max_seq * sizeof(xzk_seq_t));
    ctx->buf_ll = malloc(max_seq * sizeof(uint32_t));
    ctx->buf_ml = malloc(max_seq * sizeof(uint32_t));
    ctx->buf_off = malloc(max_seq * sizeof(uint32_t));
    ctx->literals = malloc(chunk_size);
    ctx->max_seq_count = max_seq;
    if (!ctx->hash_table || !ctx->sequences || !ctx->buf_ll || !ctx->buf_ml || !ctx->buf_off || !ctx->literals)
        return -1;
    return 0;
}

void xzk_cctx_free(xzk_cctx_t *ctx)
{
    free(ctx->hash_table);
    free(ctx->sequences);
    free(ctx->buf_ll);
    free(ctx->buf_ml);
    free(ctx->buf_off);
    free(ctx->literals);
}

// --- XXH32 Checksum ---
#define PRIME32_1 2654435761U
#define PRIME32_2 2246822507U
#define PRIME32_3 3266489917U
#define PRIME32_4 668265263U
#define PRIME32_5 374761393U

typedef struct
{
    uint32_t v1, v2, v3, v4;
    uint32_t seed;
} xzk_xxh32_state_t;

static inline void xzk_xxh32_init(xzk_xxh32_state_t *state, uint32_t seed)
{
    state->seed = seed;
    state->v1 = seed + PRIME32_1 + PRIME32_2;
    state->v2 = seed + PRIME32_2;
    state->v3 = seed;
    state->v4 = seed - PRIME32_1;
}

static inline void xzk_xxh32_update_stripes(xzk_xxh32_state_t *state, const uint8_t *input, size_t len)
{
    const uint8_t *p = input;
    const uint8_t *const limit = input + len;
#if defined(XZK_USE_SSE41)
    __m128i vec_v = _mm_setr_epi32(state->v1, state->v2, state->v3, state->v4);
    __m128i vec_prime2 = _mm_set1_epi32((int)PRIME32_2), vec_prime1 = _mm_set1_epi32((int)PRIME32_1);
    while (p < limit)
    {
        __m128i vec_in = _mm_loadu_si128((const __m128i *)p);
        vec_v = _mm_add_epi32(vec_v, _mm_mullo_epi32(vec_in, vec_prime2));
        vec_v = _mm_mullo_epi32(_mm_or_si128(_mm_slli_epi32(vec_v, 13), _mm_srli_epi32(vec_v, 19)), vec_prime1);
        p += 16;
    }
    state->v1 = _mm_cvtsi128_si32(vec_v);
    state->v2 = _mm_cvtsi128_si32(_mm_shuffle_epi32(vec_v, 85));
    state->v3 = _mm_cvtsi128_si32(_mm_shuffle_epi32(vec_v, 170));
    state->v4 = _mm_cvtsi128_si32(_mm_shuffle_epi32(vec_v, 255));
#else
    uint32_t v1 = state->v1, v2 = state->v2, v3 = state->v3, v4 = state->v4;
    while (p < limit)
    {
        v1 += xzk_le32(p) * PRIME32_2;
        v1 = (v1 << 13) | (v1 >> 19);
        v1 *= PRIME32_1;
        p += 4;
        v2 += xzk_le32(p) * PRIME32_2;
        v2 = (v2 << 13) | (v2 >> 19);
        v2 *= PRIME32_1;
        p += 4;
        v3 += xzk_le32(p) * PRIME32_2;
        v3 = (v3 << 13) | (v3 >> 19);
        v3 *= PRIME32_1;
        p += 4;
        v4 += xzk_le32(p) * PRIME32_2;
        v4 = (v4 << 13) | (v4 >> 19);
        v4 *= PRIME32_1;
        p += 4;
    }
    state->v1 = v1;
    state->v2 = v2;
    state->v3 = v3;
    state->v4 = v4;
#endif
}

static inline uint32_t xzk_xxh32_digest(xzk_xxh32_state_t *state, const uint8_t *tail, size_t tail_len, size_t total_len)
{
    uint32_t h32 = (total_len >= 16) ? ((state->v1 << 1) | (state->v1 >> 31)) + ((state->v2 << 7) | (state->v2 >> 25)) + ((state->v3 << 12) | (state->v3 >> 20)) + ((state->v4 << 18) | (state->v4 >> 14)) : state->seed + PRIME32_5;
    h32 += (uint32_t)total_len;
    const uint8_t *p = tail, *bEnd = tail + tail_len;
    while (p + 4 <= bEnd)
    {
        h32 += xzk_le32(p) * PRIME32_3;
        h32 = ((h32 << 17) | (h32 >> 15)) * PRIME32_4;
        p += 4;
    }
    while (p < bEnd)
    {
        h32 += (*p) * PRIME32_5;
        h32 = ((h32 << 11) | (h32 >> 21)) * PRIME32_1;
        p++;
    }
    h32 ^= h32 >> 15;
    h32 *= PRIME32_2;
    h32 ^= h32 >> 13;
    h32 *= PRIME32_3;
    h32 ^= h32 >> 16;
    return h32;
}

uint32_t xzk_xxh32(const void *restrict input, size_t len, uint32_t seed)
{
    if (len < 16)
    {
        xzk_xxh32_state_t s = {0};
        s.seed = seed;
        return xzk_xxh32_digest(&s, (const uint8_t *)input, len, len);
    }
    xzk_xxh32_state_t state;
    xzk_xxh32_init(&state, seed);
    xzk_xxh32_update_stripes(&state, (const uint8_t *)input, len & ~15);
    return xzk_xxh32_digest(&state, (const uint8_t *)input + (len & ~15), len & 15, len);
}

uint32_t xzk_copy_and_checksum(const uint8_t *src, uint8_t *dst, size_t len, uint32_t seed)
{
    xzk_xxh32_state_t state;
    xzk_xxh32_init(&state, seed);
    const uint8_t *p_src = src;
    uint8_t *p_dst = dst;
    size_t remaining = len;
#if defined(XZK_USE_SSE41)
    __m128i vec_v = _mm_setr_epi32(state.v1, state.v2, state.v3, state.v4);
    __m128i vec_prime2 = _mm_set1_epi32((int)PRIME32_2), vec_prime1 = _mm_set1_epi32((int)PRIME32_1);
    while (remaining >= 16)
    {
        __m128i vec_in = _mm_loadu_si128((const __m128i *)p_src);
        _mm_storeu_si128((__m128i *)p_dst, vec_in);
        vec_v = _mm_add_epi32(vec_v, _mm_mullo_epi32(vec_in, vec_prime2));
        vec_v = _mm_mullo_epi32(_mm_or_si128(_mm_slli_epi32(vec_v, 13), _mm_srli_epi32(vec_v, 19)), vec_prime1);
        p_src += 16;
        p_dst += 16;
        remaining -= 16;
    }
    state.v1 = _mm_cvtsi128_si32(vec_v);
    state.v2 = _mm_cvtsi128_si32(_mm_shuffle_epi32(vec_v, 85));
    state.v3 = _mm_cvtsi128_si32(_mm_shuffle_epi32(vec_v, 170));
    state.v4 = _mm_cvtsi128_si32(_mm_shuffle_epi32(vec_v, 255));
#else
    while (remaining >= 16)
    {
        memcpy(p_dst, p_src, 16);
        xzk_xxh32_update_stripes(&state, p_src, 16);
        p_src += 16;
        p_dst += 16;
        remaining -= 16;
    }
#endif
    if (remaining > 0)
        memcpy(p_dst, p_src, remaining);
    return xzk_xxh32_digest(&state, p_src, remaining, len);
}

// --- Headers I/O ---
int xzk_write_file_header(uint8_t *dst, size_t dst_capacity)
{
    if (UNLIKELY(dst_capacity < XZK_FILE_HEADER_SIZE))
        return -1;
    xzk_store_le32(dst, XZK_MAGIC_WORD);
    dst[4] = XZK_VERSION;
    dst[5] = 0;
    dst[6] = 0;
    dst[7] = 0;
    return XZK_FILE_HEADER_SIZE;
}
int xzk_read_file_header(const uint8_t *src, size_t src_size)
{
    if (UNLIKELY(src_size < XZK_FILE_HEADER_SIZE))
        return -1;
    if (UNLIKELY(xzk_le32(src) != XZK_MAGIC_WORD || src[4] != XZK_VERSION))
        return -1;
    return 0;
}
int xzk_write_block_header(uint8_t *dst, size_t dst_capacity, const xzk_block_header_t *bh)
{
    if (UNLIKELY(dst_capacity < XZK_BLOCK_HEADER_SIZE))
        return -1;
    dst[0] = bh->block_type;
    dst[1] = bh->block_flags;
    xzk_store_le16(dst + 2, bh->reserved);
    xzk_store_le32(dst + 4, bh->comp_size);
    xzk_store_le32(dst + 8, bh->raw_size);
    return XZK_BLOCK_HEADER_SIZE;
}
int xzk_read_block_header(const uint8_t *src, size_t src_size, xzk_block_header_t *bh)
{
    if (UNLIKELY(src_size < XZK_BLOCK_HEADER_SIZE))
        return -1;
    bh->block_type = src[0];
    bh->block_flags = src[1];
    bh->reserved = xzk_le16(src + 2);
    bh->comp_size = xzk_le32(src + 4);
    bh->raw_size = xzk_le32(src + 8);
    return 0;
}
// Bitpacking & Subheaders
void xzk_br_init(xzk_bit_reader_t *br, const uint8_t *src, size_t size)
{
    br->ptr = src;
    br->end = src + size;
    br->accum = 0;
    br->bits = 0;
    if (size >= 8)
    {
        br->accum = xzk_le64(br->ptr);
        br->ptr += 8;
        br->bits = 64;
    }
    else
    {
        while (br->ptr < br->end)
        {
            br->accum |= ((uint64_t)(*br->ptr++)) << br->bits;
            br->bits += 8;
        }
    }
}
uint32_t xzk_br_get(xzk_bit_reader_t *br, uint8_t n)
{
    if (UNLIKELY(br->bits < n))
    {
        size_t remaining = (size_t)(br->end - br->ptr);
        if (LIKELY(remaining >= 8))
        {
            int bytes = (64 - br->bits) >> 3;
            uint64_t v = xzk_le64(br->ptr);
            br->accum |= (v << br->bits);
            br->ptr += bytes;
            br->bits += bytes * 8;
        }
        else
        {
            while (remaining > 0 && br->bits <= 56)
            {
                br->accum |= ((uint64_t)(*br->ptr)) << br->bits;
                br->ptr++;
                remaining--;
                br->bits += 8;
            }
        }
    }
    uint32_t val = (uint32_t)(br->accum & ((1UL << n) - 1));
    br->accum >>= n;
    br->bits -= n;
    return val;
}
int xzk_bitpack_stream_32(const uint32_t *restrict src, size_t count, uint8_t *restrict dst, size_t dst_cap, uint8_t bits)
{
    size_t out_bytes = ((count * bits) + 7) / 8;
    if (UNLIKELY(dst_cap < out_bytes))
        return -1;
    size_t bit_pos = 0;
    memset(dst, 0, out_bytes);
    for (size_t i = 0; i < count; i++)
    {
        uint64_t v = (uint64_t)src[i] << (bit_pos % 8);
        size_t byte_idx = bit_pos / 8;
        dst[byte_idx] |= (uint8_t)v;
        if (bits + (bit_pos % 8) > 8)
            dst[byte_idx + 1] |= (uint8_t)(v >> 8);
        if (bits + (bit_pos % 8) > 16)
            dst[byte_idx + 2] |= (uint8_t)(v >> 16);
        if (bits + (bit_pos % 8) > 24)
            dst[byte_idx + 3] |= (uint8_t)(v >> 24);
        if (bits + (bit_pos % 8) > 32)
            dst[byte_idx + 4] |= (uint8_t)(v >> 32);
        bit_pos += bits;
    }
    return (int)out_bytes;
}
int xzk_write_num_header(uint8_t *dst, size_t rem, const xzk_num_header_t *nh)
{
    if (UNLIKELY(rem < XZK_NUM_HEADER_BINARY_SIZE))
        return -1;
    xzk_store_le64(dst, nh->n_values);
    xzk_store_le16(dst + 8, nh->frame_size);
    xzk_store_le16(dst + 10, 0);
    xzk_store_le32(dst + 12, 0);
    return XZK_NUM_HEADER_BINARY_SIZE;
}
int xzk_read_num_header(const uint8_t *src, size_t src_size, xzk_num_header_t *nh)
{
    if (UNLIKELY(src_size < XZK_NUM_HEADER_BINARY_SIZE))
        return -1;
    nh->n_values = xzk_le64(src);
    nh->frame_size = xzk_le16(src + 8);
    return 0;
}
int xzk_write_gnr_header_and_desc(uint8_t *dst, size_t rem, const xzk_gnr_header_t *gh, const xzk_section_desc_t desc[4])
{
    size_t needed = XZK_GNR_HEADER_BINARY_SIZE + 4 * XZK_SECTION_DESC_BINARY_SIZE;
    if (UNLIKELY(rem < needed))
        return -1;
    xzk_store_le32(dst, gh->n_sequences);
    xzk_store_le32(dst + 4, gh->n_literals);
    dst[8] = gh->enc_lit;
    dst[9] = gh->enc_litlen;
    dst[10] = gh->enc_mlen;
    dst[11] = gh->enc_off;
    xzk_store_le32(dst + 12, 0);
    uint8_t *p = dst + XZK_GNR_HEADER_BINARY_SIZE;
    for (int i = 0; i < 4; i++)
    {
        xzk_store_le32(p, desc[i].comp_size);
        xzk_store_le32(p + 4, desc[i].raw_size);
        xzk_store_le32(p + 8, 0);
        p += 12;
    }
    return (int)needed;
}
int xzk_read_gnr_header_and_desc(const uint8_t *src, size_t len, xzk_gnr_header_t *gh, xzk_section_desc_t desc[4])
{
    size_t needed = XZK_GNR_HEADER_BINARY_SIZE + 4 * XZK_SECTION_DESC_BINARY_SIZE;
    if (UNLIKELY(len < needed))
        return -1;
    gh->n_sequences = xzk_le32(src);
    gh->n_literals = xzk_le32(src + 4);
    gh->enc_lit = src[8];
    gh->enc_litlen = src[9];
    gh->enc_mlen = src[10];
    gh->enc_off = src[11];
    const uint8_t *p = src + XZK_GNR_HEADER_BINARY_SIZE;
    for (int i = 0; i < 4; i++)
    {
        desc[i].comp_size = xzk_le32(p);
        desc[i].raw_size = xzk_le32(p + 4);
        p += 12;
    }
    return 0;
}

size_t xzk_max_compressed_size(size_t input_size)
{
    size_t n = (input_size + XZK_CHUNK_SIZE - 1) / XZK_CHUNK_SIZE;
    if (n == 0)
        n = 1;
    return XZK_FILE_HEADER_SIZE + (n * (XZK_BLOCK_HEADER_SIZE + 4 + 64)) + input_size;
}

// --- MOTEUR DE STREAMING (Reader/Worker/Writer) ---

typedef enum
{
    JOB_STATUS_FREE,
    JOB_STATUS_FILLED,
    JOB_STATUS_PROCESSED
} job_status_t;

typedef struct
{
    uint8_t *in_buf;
    size_t in_cap, in_sz;
    uint8_t *out_buf;
    size_t out_cap, result_sz;
    int job_id;
    job_status_t status;
    char pad[64];
} xzk_stream_job_t;

typedef struct
{
    xzk_stream_job_t *jobs;
    int ring_size;
    int *worker_queue;
    int wq_head, wq_tail, wq_count;
    pthread_mutex_t lock;
    pthread_cond_t cond_reader, cond_worker, cond_writer;
    int shutdown_workers;
    int compression_mode;
    xzk_chunk_processor_t processor; // Le callback générique
    // Pour le writer
    int write_idx;
} xzk_stream_ctx_t;

// Thread Worker
static void *xzk_stream_worker(void *arg)
{
    xzk_stream_ctx_t *ctx = (xzk_stream_ctx_t *)arg;
    xzk_cctx_t cctx;
    if (ctx->compression_mode && xzk_cctx_init(&cctx, XZK_CHUNK_SIZE) != 0)
        return NULL;

    while (1)
    {
        xzk_stream_job_t *job = NULL;
        pthread_mutex_lock(&ctx->lock);
        while (ctx->wq_count == 0 && !ctx->shutdown_workers)
        {
            pthread_cond_wait(&ctx->cond_worker, &ctx->lock);
        }
        if (ctx->shutdown_workers && ctx->wq_count == 0)
        {
            pthread_mutex_unlock(&ctx->lock);
            break;
        }
        int jid = ctx->worker_queue[ctx->wq_tail];
        ctx->wq_tail = (ctx->wq_tail + 1) % ctx->ring_size;
        ctx->wq_count--;
        job = &ctx->jobs[jid];
        pthread_mutex_unlock(&ctx->lock);

        if (ctx->compression_mode)
        {
            job->result_sz = ctx->processor(&cctx, job->in_buf, job->in_sz, job->out_buf, job->out_cap);
        }
        else
        {
            job->result_sz = ctx->processor(NULL, job->in_buf, job->in_sz, job->out_buf, job->out_cap);
        }

        pthread_mutex_lock(&ctx->lock);
        job->status = JOB_STATUS_PROCESSED;
        if (jid == ctx->write_idx)
            pthread_cond_broadcast(&ctx->cond_writer);
        pthread_mutex_unlock(&ctx->lock);
    }
    if (ctx->compression_mode)
        xzk_cctx_free(&cctx);
    return NULL;
}

typedef struct
{
    xzk_stream_ctx_t *ctx;
    FILE *f;
    int total_bytes;
} writer_args_t;

static void *xzk_async_writer(void *arg)
{
    writer_args_t *args = (writer_args_t *)arg;
    xzk_stream_ctx_t *ctx = args->ctx;
    while (1)
    {
        xzk_stream_job_t *job = &ctx->jobs[ctx->write_idx];
        pthread_mutex_lock(&ctx->lock);
        while (job->status != JOB_STATUS_PROCESSED)
            pthread_cond_wait(&ctx->cond_writer, &ctx->lock);

        if (job->result_sz == (size_t)-1)
        {
            pthread_mutex_unlock(&ctx->lock);
            break;
        }
        pthread_mutex_unlock(&ctx->lock);

        if (args->f && job->result_sz > 0)
            fwrite(job->out_buf, 1, job->result_sz, args->f);
        args->total_bytes += job->result_sz;

        pthread_mutex_lock(&ctx->lock);
        job->status = JOB_STATUS_FREE;
        ctx->write_idx = (ctx->write_idx + 1) % ctx->ring_size;
        pthread_cond_signal(&ctx->cond_reader);
        pthread_mutex_unlock(&ctx->lock);
    }
    return NULL;
}

int xzk_stream_engine_run(FILE *f_in, FILE *f_out, int n_threads, int mode, xzk_chunk_processor_t func)
{
    xzk_stream_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.compression_mode = mode;
    ctx.processor = func;
    int num_threads = (n_threads > 0) ? n_threads : (int)sysconf(_SC_NPROCESSORS_ONLN);
    ctx.ring_size = num_threads * 4;

    size_t max_out = xzk_max_compressed_size(XZK_CHUNK_SIZE);
    size_t alloc_in = (mode) ? XZK_CHUNK_SIZE : max_out;
    size_t alloc_out = (mode) ? max_out : XZK_CHUNK_SIZE;

    uint8_t *mem_block = malloc(ctx.ring_size * (sizeof(xzk_stream_job_t) + sizeof(int) + alloc_in + alloc_out));
    if (!mem_block)
        return -1;
    uint8_t *ptr = mem_block;
    ctx.jobs = (xzk_stream_job_t *)ptr;
    ptr += ctx.ring_size * sizeof(xzk_stream_job_t);
    ctx.worker_queue = (int *)ptr;
    ptr += ctx.ring_size * sizeof(int);
    uint8_t *buf_in = ptr;
    ptr += ctx.ring_size * alloc_in;
    uint8_t *buf_out = ptr;

    for (int i = 0; i < ctx.ring_size; i++)
    {
        ctx.jobs[i].job_id = i;
        ctx.jobs[i].status = JOB_STATUS_FREE;
        ctx.jobs[i].in_buf = buf_in + (i * alloc_in);
        ctx.jobs[i].in_cap = alloc_in;
        ctx.jobs[i].out_buf = buf_out + (i * alloc_out);
        ctx.jobs[i].out_cap = alloc_out;
        ctx.jobs[i].result_sz = 0;
    }

    pthread_mutex_init(&ctx.lock, NULL);
    pthread_cond_init(&ctx.cond_reader, NULL);
    pthread_cond_init(&ctx.cond_worker, NULL);
    pthread_cond_init(&ctx.cond_writer, NULL);

    pthread_t *workers = malloc(num_threads * sizeof(pthread_t));
    for (int i = 0; i < num_threads; i++)
        pthread_create(&workers[i], NULL, xzk_stream_worker, &ctx);

    writer_args_t w_args = {&ctx, f_out, 0};
    if (mode == 1 && f_out)
    {
        uint8_t h[8];
        xzk_write_file_header(h, 8);
        fwrite(h, 1, 8, f_out);
        w_args.total_bytes = 8;
    }
    pthread_t writer_th;
    pthread_create(&writer_th, NULL, xzk_async_writer, &w_args);

    int read_idx = 0;
    int read_eof = 0;

    if (mode == 0 && f_in)
    {
        uint8_t h[8];
        if (fread(h, 1, 8, f_in) != 8 || xzk_read_file_header(h, 8) != 0)
            read_eof = 1;
    }

    while (!read_eof && f_in)
    {
        xzk_stream_job_t *job = &ctx.jobs[read_idx];
        pthread_mutex_lock(&ctx.lock);
        while (job->status != JOB_STATUS_FREE)
            pthread_cond_wait(&ctx.cond_reader, &ctx.lock);
        pthread_mutex_unlock(&ctx.lock);

        size_t read_sz = 0;
        if (mode == 1)
        {
            read_sz = fread(job->in_buf, 1, XZK_CHUNK_SIZE, f_in);
            if (read_sz == 0)
                read_eof = 1;
        }
        else
        {
            uint8_t bh_buf[XZK_BLOCK_HEADER_SIZE + 4];
            size_t h_read = fread(bh_buf, 1, XZK_BLOCK_HEADER_SIZE, f_in);
            if (h_read < XZK_BLOCK_HEADER_SIZE)
            {
                read_eof = 1;
            }
            else
            {
                xzk_block_header_t bh;
                xzk_read_block_header(bh_buf, XZK_BLOCK_HEADER_SIZE, &bh);
                int has_crc = (bh.block_flags & XZK_BLOCK_FLAG_CHECKSUM);
                if (has_crc)
                    fread(bh_buf + XZK_BLOCK_HEADER_SIZE, 1, 4, f_in);
                memcpy(job->in_buf, bh_buf, XZK_BLOCK_HEADER_SIZE + (has_crc ? 4 : 0));
                size_t body_read = fread(job->in_buf + XZK_BLOCK_HEADER_SIZE + (has_crc ? 4 : 0), 1, bh.comp_size, f_in);
                read_sz = XZK_BLOCK_HEADER_SIZE + (has_crc ? 4 : 0) + body_read;
                if (body_read != bh.comp_size)
                    read_eof = 1;
            }
        }
        if (read_eof && read_sz == 0)
            break;

        job->in_sz = read_sz;
        pthread_mutex_lock(&ctx.lock);
        job->status = JOB_STATUS_FILLED;
        ctx.worker_queue[ctx.wq_head] = read_idx;
        ctx.wq_head = (ctx.wq_head + 1) % ctx.ring_size;
        ctx.wq_count++;
        read_idx = (read_idx + 1) % ctx.ring_size;
        pthread_cond_signal(&ctx.cond_worker);
        pthread_mutex_unlock(&ctx.lock);

        if (read_sz < XZK_CHUNK_SIZE && mode == 1)
            read_eof = 1;
    }

    xzk_stream_job_t *end_job = &ctx.jobs[read_idx];
    pthread_mutex_lock(&ctx.lock);
    while (end_job->status != JOB_STATUS_FREE)
        pthread_cond_wait(&ctx.cond_reader, &ctx.lock);
    end_job->result_sz = -1;
    end_job->status = JOB_STATUS_PROCESSED;
    pthread_cond_broadcast(&ctx.cond_writer);
    pthread_mutex_unlock(&ctx.lock);

    pthread_join(writer_th, NULL);
    pthread_mutex_lock(&ctx.lock);
    ctx.shutdown_workers = 1;
    pthread_cond_broadcast(&ctx.cond_worker);
    pthread_mutex_unlock(&ctx.lock);
    for (int i = 0; i < num_threads; i++)
        pthread_join(workers[i], NULL);

    free(workers);
    free(mem_block);
    return w_args.total_bytes;
}
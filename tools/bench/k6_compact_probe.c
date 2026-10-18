/* Experimental K6 low-ID lookup, NOT linked into toks.
 * Exactness: every low-ID pair and last-wins merge rank, high-ID fallback.
 * Shared-runner microbenchmarks are exploratory, NOT production speed evidence.
 */
#define _POSIX_C_SOURCE 200809L
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#define LOW 1024u
#define WORDS (LOW * LOW / 64u)
#define NONE UINT32_MAX
#define MAX_PAIRS (1u << 21)
#define READ_U32(p) ((uint32_t)(p)[0] | ((uint32_t)(p)[1] << 8) | ((uint32_t)(p)[2] << 16) | ((uint32_t)(p)[3] << 24))
typedef struct { uint32_t l, r, rank; } pair;
typedef struct { uint32_t l, r; } query;
typedef struct {
    uint64_t bitmap[WORDS];
    uint16_t prefix[WORDS];
    uint32_t row[LOW + 1];
    uint32_t *prios;
    uint32_t nlow;
} compact;
static volatile uint64_t sink;
static void fail(const char *why) { fprintf(stderr, "K6 COMPACT FAIL: %s\n", why); exit(2); }
static uint64_t key(uint32_t l, uint32_t r) { return ((uint64_t)l << 21) | r; }
static uint32_t find_sorted(const pair *p, size_t n, uint32_t l, uint32_t r)
{
    uint64_t target = key(l, r);
    size_t lo = 0, hi = n;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        uint64_t k = key(p[mid].l, p[mid].r);
        if (k < target) { lo = mid + 1; } else { hi = mid; }
    }
    return lo < n && key(p[lo].l, p[lo].r) == target ? p[lo].rank : NONE;
}
static pair *read_file(const char *name, size_t *n, uint32_t *vocab, uint32_t *raw)
{
    FILE *f = fopen(name, "rb");
    if (!f) { fail("cannot open binary fixture"); }
    uint8_t h[20];
    if (fread(h, 1, 20, f) != 20 || memcmp(h, "K6CMP1\0\0", 8) != 0) { fail("bad fixture magic"); }
    *n = READ_U32(h + 8); *vocab = READ_U32(h + 12); *raw = READ_U32(h + 16);
    if (*n > MAX_PAIRS || *n > *raw || *vocab == 0) { fail("bad fixture count"); }
    pair *p = malloc((*n ? *n : 1) * sizeof(*p));
    if (!p) { fail("pairs allocation"); }
    uint64_t prev = 0;
    for (size_t i = 0; i < *n; ++i) {
        uint8_t item[12];
        if (fread(item, 1, 12, f) != 12) { fail("truncated fixture"); }
        p[i].l = READ_U32(item); p[i].r = READ_U32(item + 4); p[i].rank = READ_U32(item + 8);
        uint64_t k = key(p[i].l, p[i].r);
        if (p[i].l >= (1u << 21) || p[i].r >= (1u << 21) || p[i].rank >= *raw ||
            (i > 0 && k <= prev)) { fail("invalid pair order, ID, or rank"); }
        prev = k;
    }
    if (fgetc(f) != EOF) { fail("fixture has trailing bytes"); }
    fclose(f);
    return p;
}
static compact *build(const pair *p, size_t n)
{
    compact *c = calloc(1, sizeof(*c));
    if (!c) { fail("compact table allocation"); }
    uint32_t counts[LOW] = {0};
    for (size_t i = 0; i < n; ++i) {
        if (p[i].l < LOW && p[i].r < LOW) {
            uint32_t w = (p[i].l << 4) + (p[i].r >> 6);
            c->bitmap[w] |= UINT64_C(1) << (p[i].r & 63u);
            ++counts[p[i].l];
            ++c->nlow;
        }
    }
    c->prios = malloc((c->nlow ? c->nlow : 1) * sizeof(uint32_t));
    if (!c->prios) { fail("priority vector allocation"); }
    uint32_t j = 0;
    for (size_t i = 0; i < n; ++i) {
        if (p[i].l < LOW && p[i].r < LOW) { c->prios[j++] = p[i].rank; }
    }
    if (j != c->nlow) { fail("priority array length"); }
    for (uint32_t l = 0; l < LOW; ++l) {
        c->row[l + 1u] = c->row[l] + counts[l];
        uint32_t seen = 0;
        for (uint32_t w = 0; w < 16u; ++w) {
            uint32_t at = (l << 4) + w;
            c->prefix[at] = (uint16_t)seen;
            seen += (uint32_t)__builtin_popcountll(c->bitmap[at]);
        }
        if (seen != counts[l] || seen > LOW) { fail("rank-index invariant"); }
    }
    if (c->row[LOW] != c->nlow) { fail("row index invariant"); }
    return c;
}
static uint32_t find_compact(const compact *c, const pair *all, size_t n, uint32_t l, uint32_t r)
{
    if (l >= LOW || r >= LOW) { return find_sorted(all, n, l, r); }
    uint32_t word = (l << 4) + (r >> 6);
    uint64_t bits = c->bitmap[word], mask = UINT64_C(1) << (r & 63u);
    if ((bits & mask) == 0) { return NONE; }
    uint32_t idx = c->row[l] + c->prefix[word] + (uint32_t)__builtin_popcountll(bits & (mask - 1u));
    if (idx >= c->nlow) { fail("lookup index out of range"); }
    return c->prios[idx];
}
static uint32_t *dense_build(const pair *all, size_t n)
{
    uint32_t *dense = malloc((size_t)LOW * LOW * sizeof(uint32_t));
    if (!dense) { fail("dense array allocation"); }
    memset(dense, 0xFF, (size_t)LOW * LOW * sizeof(uint32_t));
    for (size_t i = 0; i < n; i++) {
        if (all[i].l < LOW && all[i].r < LOW) {
            dense[(all[i].l << 10) | all[i].r] = all[i].rank;
        }
    }
    return dense;
}
static uint64_t rng = UINT64_C(0x4b364e1f2257ac91);
static uint32_t rand32(void) { rng ^= rng << 13; rng ^= rng >> 7; rng ^= rng << 17; return (uint32_t)(rng >> 16); }
static double now_s(void) { struct timespec t; if (clock_gettime(CLOCK_MONOTONIC, &t)) { fail("clock_gettime"); } return (double)t.tv_sec + 1e-9 * t.tv_nsec; }
static void verify(const pair *p, size_t n, const compact *c, const uint32_t *dense)
{
    uint64_t compared = 0;
    for (uint32_t l = 0; l < LOW; ++l) {
        for (uint32_t r = 0; r < LOW; ++r) {
            uint32_t expected = dense[(l << 10) | r];
            uint32_t got = find_compact(c, p, n, l, r);
            if (expected != got) { fail("exhaustive low-ID mismatch"); }
            ++compared;
        }
    }
    for (size_t i = 0; i < n; ++i) {
        uint32_t got = find_compact(c, p, n, p[i].l, p[i].r);
        if (got != p[i].rank) { fail("present-pair priority mismatch"); }
        ++compared;
    }
    for (uint32_t i = 0; i < 100000u; ++i) {
        uint32_t l = (i & 1u) ? LOW + (rand32() % 120000u) : rand32() % LOW;
        uint32_t r = (i & 2u) ? LOW + (rand32() % 120000u) : rand32() % LOW;
        if (find_compact(c, p, n, l, r) != find_sorted(p, n, l, r)) { fail("high/miss random mismatch"); }
        ++compared;
    }
    printf("VERIFIED exhaustive_low=1048576 present=%zu random_gate=100000 compared=%" PRIu64 " mismatches=0\n", n, compared);
}
static void microbench(const pair *p, size_t n, const compact *c, const uint32_t *dense)
{
    const size_t N = 200000u;
    query *q = malloc(N * sizeof(*q));
    query *hits = malloc((c->nlow ? c->nlow : 1) * sizeof(*hits));
    if (!q || !hits) { fail("query stream allocation"); }
    uint32_t h = 0;
    for (size_t i = 0; i < n; ++i) {
        if (p[i].l < LOW && p[i].r < LOW) { hits[h++] = (query){p[i].l, p[i].r}; }
    }
    if (h != c->nlow) { fail("hit index invariant"); }
    for (uint32_t hit_rate = 0; hit_rate <= 100; hit_rate += 50) {
        for (size_t i = 0; i < N; ++i) {
            if (c->nlow && rand32() % 100 < hit_rate) {
                q[i] = hits[rand32() % c->nlow];
            } else {
                uint32_t l, r;
                do { l = rand32() % LOW; r = rand32() % LOW; }
                while (dense[(l << 10) | r] != NONE);
                q[i] = (query){l, r};
            }
        }
        for (int trial = 0; trial < 4; ++trial) {
            int candidate = trial == 0 || trial == 3;
            uint64_t sum = 0;
            double start = now_s();
            for (size_t i = 0; i < N; ++i) {
                uint32_t id = candidate ? find_compact(c, p, n, q[i].l, q[i].r) : dense[(q[i].l << 10) | q[i].r];
                sum += id;
            }
            sink += sum;
            double elapsed = now_s() - start;
            printf("MICROBENCH sampled_hit_pct=%u trial=%d candidate=%s ns_per_lookup=%.2f\n",
                   hit_rate, trial, candidate ? "compact" : "dense", elapsed * 1e9 / N);
        }
    }
    free(hits);
    free(q);
}
int main(int argc, char **argv)
{
    if (argc != 2 && argc != 3) { fprintf(stderr, "usage: %s fixture.bin [--bench]\n", argv[0]); return 2; }
    if (argc == 3 && strcmp(argv[2], "--bench") != 0) { fail("invalid option"); }
    size_t n = 0; uint32_t vocab = 0, raw = 0;
    pair *p = read_file(argv[1], &n, &vocab, &raw);
    compact *c = build(p, n);
    uint32_t *dense = dense_build(p, n);
    size_t cbytes = sizeof(*c) + c->nlow * sizeof(uint32_t);
    printf("MODEL vocab=%" PRIu32 " raw_merges=%" PRIu32 " unique_pairs=%zu low_pairs=%" PRIu32
           " dense_bytes=%u compact_bytes=%zu compact_ratio=%.3f\n", vocab, raw, n, c->nlow,
           LOW * LOW * 4u, cbytes, (double)(LOW * LOW * 4u) / (double)cbytes);
    verify(p, n, c, dense);
    if (argc == 3) { microbench(p, n, c, dense); }
    free(dense); free(c->prios); free(c); free(p);
    return 0;
}

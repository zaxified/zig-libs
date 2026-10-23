// SPDX-License-Identifier: MIT

// "Fastest in the field" side of `zig build bench-trie`
// (modules/trie/tools/bench.zig): times s-yata/darts-clone 0.32h and
// s-yata/marisa-trie 0.3.1 through their public APIs on the SAME deterministic
// key set and queries as tools/rust_bench/src/main.rs (splitmix64, seed
// 0x74726965; the draw order below mirrors that file line for line).
//
//	trie_bench_cpp <lib> <row>      lib: darts | marisa | marisa-fast
//
// prints one line, tab separated, exactly like the Rust side:
//
//	row, ns per op, count, sum
//
// One op is the whole row (all 100 000 lookups, all 1 000 prefixes, ...).
// Timing matches the other two sides: double the batch until one batch takes
// over 100 ms, then keep the best of five.
//
// A row the library cannot do prints `row<TAB>unsupported`, a reason on stderr,
// and exits with status 3 (not an error: bench.zig skips that column).
//
//	row            darts-clone                marisa-trie
//	build          DoubleArray::build         Keyset + Trie::build
//	lookup_hit     exactMatchSearch           Trie::lookup
//	lookup_miss    exactMatchSearch           Trie::lookup
//	prefix_iter    unsupported (1)            Trie::predictive_search
//	range_iter     unsupported (2)            unsupported (2)
//	search_subseq  unsupported (3)            unsupported (3)
//	union_2        unsupported (4)            unsupported (4)
//	load           set_array (O(1))           Trie::map over the serialized bytes
//	size           total_size() bytes         io_size() bytes (serialized)
//
// (1) darts-clone has commonPrefixSearch = the keys that are prefixes OF the
//     query, the opposite of "every key under a prefix". It cannot enumerate.
// (2) neither stores the keys in sorted order (darts: double array, marisa:
//     LOUDS in weight order and ids in LOUDS order), so no ordered range.
// (3) no automaton interface; (4) no set operations on two indexes.
//
// Values. The fst/ours value of a key is its position in the sorted key list.
// darts-clone stores an int per key natively (build(..., values)), so the
// value comes straight out of the lookup. marisa-trie only returns a key id
// (dense, in trie order, NOT in input order), so the values live in a side
// array `val_of_id[id]` built at build time from the ids Trie::build writes
// back into the Keyset. Every marisa lookup/prefix hit therefore pays one
// extra array load, and the build row includes filling that array -- that is
// part of marisa's honest cost for a key->u32 map, not an artefact.
//
// Configurations. `marisa` is the library default (3 tries, normal cache,
// weight order: what a user gets with `marisa-build`). `marisa-fast` is the
// speed-oriented setting (1 trie, huge cache; larger, faster lookups). The
// verdict uses whichever is faster per row.

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

#include "darts.h"
#include "marisa.h"

namespace {

using u64 = std::uint64_t;

constexpr u64 SEED = 0x74726965;
constexpr std::size_t N_KEYS = 1'000'000;
constexpr std::size_t N_HIT = 100'000;
constexpr std::size_t N_MISS = 100'000;
constexpr std::size_t N_PREFIX = 1'000;
constexpr std::size_t N_RANGE = 1'000;
constexpr std::size_t N_SUBSEQ = 100;

struct SplitMix {
    u64 s;
    u64 next() {
        s += 0x9E3779B97F4A7C15ULL;
        u64 z = s;
        z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
        z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
        return z ^ (z >> 31);
    }
};

struct Row {
    u64 count;
    u64 sum;
};

// Optimizer barrier (the Rust side's std::hint::black_box).
template <class T>
inline void black_box(const T& v) {
    asm volatile("" : : "r,m"(v) : "memory");
}

struct Data {
    std::vector<std::string> keys;
    std::vector<std::size_t> hits;
    std::vector<std::string> misses;
    std::vector<std::string> prefixes;
    std::vector<std::pair<std::size_t, std::size_t>> ranges; // unused here, drawn for parity
    std::vector<std::string> subseqs;                        // unused here, drawn for parity
};

Data gen() {
    SplitMix rng{SEED};
    Data d;
    d.keys.reserve(N_KEYS);
    for (std::size_t i = 0; i < N_KEYS; ++i) {
        const u64 r = rng.next();
        std::string k;
        k.reserve(16);
        k.push_back('w');
        for (int j = 0; j < 8; ++j) k.push_back(static_cast<char>('a' + ((r >> (8 * j)) & 0xff) % 26));
        k.push_back('/');
        k += std::to_string(rng.next() % 10'000);
        d.keys.push_back(std::move(k));
    }
    // std::string order = unsigned bytewise, the same as Vec<u8>::sort.
    std::sort(d.keys.begin(), d.keys.end());
    d.keys.erase(std::unique(d.keys.begin(), d.keys.end()), d.keys.end());
    const u64 n = d.keys.size();

    for (std::size_t i = 0; i < N_HIT; ++i) d.hits.push_back(static_cast<std::size_t>(rng.next() % n));
    while (d.misses.size() < N_MISS) {
        std::string k = d.keys[rng.next() % n];
        k.back() = static_cast<char>(k.back() + 1);
        if (!std::binary_search(d.keys.begin(), d.keys.end(), k)) d.misses.push_back(std::move(k));
    }
    for (std::size_t i = 0; i < N_PREFIX; ++i) d.prefixes.push_back(d.keys[rng.next() % n].substr(0, 3));
    for (std::size_t i = 0; i < N_RANGE; ++i) {
        const std::size_t a = static_cast<std::size_t>(rng.next() % n);
        const std::size_t span = static_cast<std::size_t>(rng.next() % 1000) + 1;
        d.ranges.emplace_back(a, std::min(a + span, d.keys.size() - 1));
    }
    for (std::size_t i = 0; i < N_SUBSEQ; ++i) {
        std::string s;
        for (int j = 0; j < 3; ++j) s.push_back(static_cast<char>('a' + rng.next() % 26));
        d.subseqs.push_back(std::move(s));
    }
    return d;
}

template <class F>
std::pair<double, Row> time_it(F&& f) {
    using clock = std::chrono::steady_clock;
    u64 n = 1;
    for (;;) {
        const auto t = clock::now();
        for (u64 i = 0; i < n; ++i) {
            Row r = f();
            black_box(r);
        }
        if (clock::now() - t > std::chrono::milliseconds(100)) break;
        n *= 2;
    }
    auto best = clock::duration::max();
    Row row{0, 0};
    for (int rep = 0; rep < 5; ++rep) {
        const auto t = clock::now();
        for (u64 i = 0; i < n; ++i) {
            row = f();
            black_box(row);
        }
        best = std::min(best, clock::now() - t);
    }
    const double ns = static_cast<double>(std::chrono::duration_cast<std::chrono::nanoseconds>(best).count());
    return {ns / static_cast<double>(n), row};
}

[[noreturn]] void unsupported(const char* row, const char* why) {
    std::printf("%s\tunsupported\n", row);
    std::fprintf(stderr, "%s: unsupported by this library: %s\n", row, why);
    std::exit(3);
}

bool is(const std::string& a, const char* b) { return a == b; }

void emit(const std::string& row, std::pair<double, Row> r) {
    std::printf("%s\t%.3f\t%llu\t%llu\n", row.c_str(), r.first, static_cast<unsigned long long>(r.second.count),
                static_cast<unsigned long long>(r.second.sum));
}

// ---- darts-clone ----

void run_darts(const std::string& row, const Data& d) {
    const std::size_t n = d.keys.size();
    std::vector<const char*> kp(n);
    std::vector<std::size_t> kl(n);
    std::vector<int> kv(n);
    for (std::size_t i = 0; i < n; ++i) {
        kp[i] = d.keys[i].data();
        kl[i] = d.keys[i].size();
        kv[i] = static_cast<int>(i);
    }
    // With values given, build() takes the DAWG path (smaller than a plain
    // trie) -- the library's own recommendation for key->value maps.
    Darts::DoubleArray da;
    da.build(n, kp.data(), kl.data(), kv.data());

    std::pair<double, Row> res;
    if (is(row, "build")) {
        res = time_it([&] {
            Darts::DoubleArray t;
            t.build(n, kp.data(), kl.data(), kv.data());
            black_box(t.array());
            return Row{n, 0};
        });
    } else if (is(row, "lookup_hit")) {
        res = time_it([&] {
            u64 c = 0, s = 0;
            for (const std::size_t i : d.hits) {
                const std::string& k = d.keys[i];
                const int v = da.exactMatchSearch<int>(k.data(), k.size());
                if (v >= 0) {
                    c += 1;
                    s += static_cast<u64>(v);
                }
            }
            return Row{c, s};
        });
    } else if (is(row, "lookup_miss")) {
        res = time_it([&] {
            u64 c = 0;
            for (const std::string& k : d.misses) {
                if (da.exactMatchSearch<int>(k.data(), k.size()) < 0) c += 1;
            }
            return Row{c, 0};
        });
    } else if (is(row, "load")) {
        // set_array() just stores the pointer (the file reader `open` is the
        // O(size) alternative, not what fst's Map::new compares to). darts has
        // no key count, so the count is the one the harness knows.
        res = time_it([&] {
            Darts::DoubleArray t;
            t.set_array(da.array(), da.size());
            black_box(t.array());
            return Row{n, 0};
        });
    } else if (is(row, "size")) {
        res = {0.0, Row{da.total_size(), 0}};
    } else if (is(row, "prefix_iter")) {
        unsupported("prefix_iter", "commonPrefixSearch finds keys that are prefixes of the query, not keys under a prefix");
    } else {
        unsupported(row.c_str(), "no ordered range / automaton search / set operations");
    }
    emit(row, res);
}

// ---- marisa-trie ----

void run_marisa(const std::string& row, const Data& d, int flags) {
    const std::size_t n = d.keys.size();

    // Trie::build writes each key's id back into the Keyset entry of the SAME
    // position, so val_of_id[keyset[i].id()] = i recovers the position value.
    struct Built {
        marisa::Trie trie;
        std::vector<std::uint32_t> val_of_id;
    };
    auto build = [&](Built& b) {
        marisa::Keyset ks;
        for (const std::string& k : d.keys) ks.push_back(k.data(), k.size());
        b.trie.build(ks, flags);
        b.val_of_id.assign(n, 0);
        for (std::size_t i = 0; i < n; ++i) b.val_of_id[ks[i].id()] = static_cast<std::uint32_t>(i);
    };

    Built b;
    build(b);
    marisa::Agent agent; // reused across calls, as the library intends

    std::pair<double, Row> res;
    if (is(row, "build")) {
        res = time_it([&] {
            Built t;
            build(t);
            black_box(t.val_of_id.data());
            return Row{n, 0};
        });
    } else if (is(row, "lookup_hit")) {
        res = time_it([&] {
            u64 c = 0, s = 0;
            for (const std::size_t i : d.hits) {
                const std::string& k = d.keys[i];
                agent.set_query(k.data(), k.size());
                if (b.trie.lookup(agent)) {
                    c += 1;
                    s += b.val_of_id[agent.key().id()];
                }
            }
            return Row{c, s};
        });
    } else if (is(row, "lookup_miss")) {
        res = time_it([&] {
            u64 c = 0;
            for (const std::string& k : d.misses) {
                agent.set_query(k.data(), k.size());
                if (!b.trie.lookup(agent)) c += 1;
            }
            return Row{c, 0};
        });
    } else if (is(row, "prefix_iter")) {
        res = time_it([&] {
            u64 c = 0, s = 0;
            for (const std::string& p : d.prefixes) {
                agent.set_query(p.data(), p.size());
                while (b.trie.predictive_search(agent)) {
                    c += 1;
                    s += b.val_of_id[agent.key().id()];
                }
            }
            return Row{c, s};
        });
    } else if (is(row, "load")) {
        std::ostringstream os;
        marisa::write(os, b.trie);
        const std::string bytes = os.str(); // heap block: 16-byte aligned, the mapper wants 8
        res = time_it([&] {
            marisa::Trie t;
            t.map(bytes.data(), bytes.size());
            return Row{t.num_keys(), 0};
        });
    } else if (is(row, "size")) {
        res = {0.0, Row{b.trie.io_size(), 0}};
    } else {
        unsupported(row.c_str(), "no ordered range / automaton search / set operations");
    }
    emit(row, res);
}

} // namespace

int main(int argc, char** argv) {
    if (argc != 3) {
        std::fprintf(stderr, "usage: %s <darts|marisa|marisa-fast> <row>\n", argv[0]);
        return 2;
    }
    const std::string lib = argv[1];
    const std::string row = argv[2];
    static const char* const rows[] = {"build", "lookup_hit", "lookup_miss", "prefix_iter", "range_iter",
                                       "search_subseq", "union_2", "load", "size"};
    bool known = false;
    for (const char* r : rows) known = known || row == r;
    if (!known) {
        std::fprintf(stderr, "unknown row %s\n", row.c_str());
        return 2;
    }
    const bool is_darts = lib == "darts";
    if (!is_darts && lib != "marisa" && lib != "marisa-fast") {
        std::fprintf(stderr, "unknown lib %s\n", lib.c_str());
        return 2;
    }
    // Decide "unsupported" before the ~1 s of data generation.
    if (row == "range_iter" || row == "search_subseq" || row == "union_2")
        unsupported(row.c_str(), "no ordered range / automaton search / set operations");
    if (is_darts && row == "prefix_iter")
        unsupported("prefix_iter", "commonPrefixSearch finds keys that are prefixes of the query, not keys under a prefix");

    try {
        const Data d = gen();
        if (is_darts) {
            run_darts(row, d);
        } else if (lib == "marisa") {
            run_marisa(row, d, 0);
        } else {
            run_marisa(row, d, MARISA_MIN_NUM_TRIES | MARISA_HUGE_CACHE);
        }
    } catch (const std::exception& e) {
        std::fprintf(stderr, "%s %s: exception: %s\n", lib.c_str(), row.c_str(), e.what());
        return 1;
    }
    return 0;
}

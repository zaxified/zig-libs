// SPDX-License-Identifier: MIT

// Second side of `zig build bench-sort` (modules/sort/tools/bench.zig):
// C++ libstdc++ `std::sort` (introsort), `std::stable_sort` (merge sort with
// a buffer) and `std::nth_element` (introselect). Usage:
// `foreign_bench <work dir> <workload>`; the workload name and the input
// generator are specified in bench.zig's header, and this file follows it.
// Prints `workload \t ns/op \t user-mode cycles/op \t count`; the banner
// goes to stderr. Timing as testkit.bench: double the batch until it takes
// over 100 ms, keep the best of five.

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <functional>
#include <string>
#include <string_view>
#include <vector>

#include <linux/perf_event.h>
#include <sys/syscall.h>
#include <unistd.h>

struct SplitMix {
    uint64_t s;
    uint64_t next() {
        s += 0x9e3779b97f4a7c15ull;
        uint64_t z = s;
        z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ull;
        z = (z ^ (z >> 27)) * 0x94d049bb133111ebull;
        return z ^ (z >> 31);
    }
};

static uint64_t value(SplitMix &r, const std::string &pat, size_t i, size_t n) {
    if (pat == "rand") return r.next();
    if (pat == "dup16") return r.next() % 16;
    if (pat == "asc") return i;
    if (pat == "desc") return n - i;
    if (pat == "saw") return i % 1000;
    if (pat == "tail") return i < n - n / 100 ? i : r.next();
    fprintf(stderr, "pattern %s\n", pat.c_str());
    exit(2);
}

struct Rec {
    uint64_t key, a, b, c;
};

struct Cycles {
    int fd = -1;
    Cycles() {
        perf_event_attr attr;
        memset(&attr, 0, sizeof attr);
        attr.type = PERF_TYPE_HARDWARE;
        attr.size = sizeof attr;
        attr.config = PERF_COUNT_HW_CPU_CYCLES;
        attr.exclude_kernel = 1;
        attr.exclude_hv = 1;
        fd = (int)syscall(SYS_perf_event_open, &attr, 0, -1, -1, 0);
    }
    uint64_t read() const {
        if (fd < 0) return 0;
        uint64_t v = 0;
        if (::read(fd, &v, 8) != 8) return 0;
        return v;
    }
};

template <class F>
static void time_it(const char *name, F f) {
    using clk = std::chrono::steady_clock;
    Cycles cyc;
    uint64_t n = 1;
    volatile uint64_t sink = 0;
    for (;;) {
        auto t = clk::now();
        for (uint64_t i = 0; i < n; i++) sink = sink + f();
        if (clk::now() - t > std::chrono::milliseconds(100)) break;
        n *= 2;
    }
    double best = 1e300, best_cyc = 1e300;
    uint64_t count = 0;
    for (int k = 0; k < 5; k++) {
        auto t = clk::now();
        uint64_t c0 = cyc.read();
        for (uint64_t i = 0; i < n; i++) count = f();
        uint64_t c1 = cyc.read();
        double ns = std::chrono::duration<double, std::nano>(clk::now() - t).count();
        best = std::min(best, ns);
        best_cyc = std::min(best_cyc, double(c1 - c0));
    }
    printf("%s\t%f\t%f\t%llu\n", name, best / n, best_cyc / n, (unsigned long long)count);
}

template <class T, class Less, class Key>
static uint64_t sum_by(const std::vector<T> &w, Key key) {
    uint64_t k = 0;
    for (size_t i = 0; i < w.size(); i += 61) k += uint64_t(i + 1) * key(w[i]);  // every 61st, as bench.zig
    return k;
}

template <class T, class Less, class Key, class SelKey>
static void run(const char *name, const std::string &alg, const std::vector<T> &in, Less less, Key key, SelKey sel_key) {
    std::vector<T> w(in.size());
    time_it(name, [&]() -> uint64_t {
        std::copy(in.begin(), in.end(), w.begin());
        if (alg == "u") {
            std::sort(w.begin(), w.end(), less);
        } else if (alg == "s") {
            std::stable_sort(w.begin(), w.end(), less);
        } else {
            size_t m = w.size() / 2;
            std::nth_element(w.begin(), w.begin() + m, w.end(), less);
            return sel_key(w[m]);
        }
        return sum_by<T, Less>(w, key);
    });
}

int main(int argc, char **argv) {
    if (argc != 3) return 2;
    std::string name = argv[2];
    std::vector<std::string> parts;
    for (size_t p = 0, q; p <= name.size(); p = q + 1) {
        q = name.find('_', p);
        if (q == std::string::npos) q = name.size();
        parts.push_back(name.substr(p, q - p));
    }
    const std::string &alg = parts[0], &ty = parts[1], &pat = parts[2], &ns = parts[3];
    size_t n = std::stoul(ns.substr(0, ns.size() - 1)) * (ns.back() == 'k' ? 1000 : 1000000);
    SplitMix r{0x5eed};
    fprintf(stderr, "C++ libstdc++ %d (std::sort / std::stable_sort / std::nth_element), g++ %d.%d\n", _GLIBCXX_RELEASE, __GNUC__, __GNUC_MINOR__);
    if (ty == "u64") {
        std::vector<uint64_t> v(n);
        for (size_t i = 0; i < n; i++) v[i] = value(r, pat, i, n);
        run(name.c_str(), alg, v, std::less<uint64_t>(), [](uint64_t x) { return x; }, [](uint64_t x) { return x; });
    } else if (ty == "u32") {
        std::vector<uint32_t> v(n);
        for (size_t i = 0; i < n; i++) {
            uint64_t x = value(r, pat, i, n);
            v[i] = pat == "rand" ? uint32_t(x >> 32) : uint32_t(x);
        }
        run(name.c_str(), alg, v, std::less<uint32_t>(), [](uint32_t x) { return uint64_t(x); }, [](uint32_t x) { return uint64_t(x); });
    } else if (ty == "rec") {
        std::vector<Rec> v(n);
        for (size_t i = 0; i < n; i++) v[i] = Rec{value(r, pat, i, n), i, ~uint64_t(i), 3 * uint64_t(i)};
        bool stable = alg == "s";
        run(name.c_str(), alg, v, [](const Rec &a, const Rec &b) { return a.key < b.key; },
            [stable](const Rec &x) { return stable ? x.a : x.key; }, [](const Rec &x) { return x.key; });
    } else if (ty == "str") {
        std::vector<std::string> owned(n);
        for (size_t i = 0; i < n; i++) {
            size_t len = 4 + r.next() % 21;
            owned[i].resize(len);
            for (size_t j = 0; j < len; j++) owned[i][j] = char('a' + r.next() % 26);
        }
        std::vector<std::string_view> v(owned.begin(), owned.end());
        run(name.c_str(), alg, v, std::less<std::string_view>(),
            [](std::string_view x) { return uint64_t(x.size()) + uint8_t(x[0]); }, [](std::string_view x) { return uint64_t(uint8_t(x[0])); });
    } else {
        return 2;
    }
    return 0;
}

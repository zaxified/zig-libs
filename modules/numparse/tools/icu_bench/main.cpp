// SPDX-License-Identifier: MIT

// "Fastest in the field" side of `zig build bench-numparse`
// (modules/numparse/tools/bench.zig): ICU4C's DecimalFormat::parse, the system
// libicu (`pkg-config icu-i18n`; ICU 78.2 on the measuring host), strict -- the
// default, `isLenient()` false -- over the same workload files the Babel side
// reads. Built by `build.sh` next to this file; no ICU source is compiled.
//
//	icu_bench <work dir> <workload>
//
// prints `name \t ns/op \t count` exactly like tools/bench_ref.py: one op parses
// every line of <work dir>/<workload>.txt once with a DecimalFormat created once
// per workload; count = (digest << 32) | accepted, digest = the sum mod 2^32 of
// the accepted values scaled by 10^12. A line is accepted when ICU parses it
// with no error AND consumes all of it (parse stops early on a trailing
// remainder; that is a refusal here, as in Babel's strict mode).
//
// ICU works in UTF-16: the UTF-8 -> UnicodeString conversion of each line is
// timed, since it is what parsing UTF-8 text with ICU costs. ICU's strict mode
// is not Babel's: the two may accept different sets of lines, which shows as a
// different `accepted` count in the bench output (the time is still the work
// of parsing all 1000 lines).

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <fstream>
#include <memory>
#include <sstream>
#include <string>
#include <vector>

#include <unicode/decimfmt.h>
#include <unicode/fmtable.h>
#include <unicode/locid.h>
#include <unicode/numfmt.h>
#include <unicode/parsepos.h>
#include <unicode/unistr.h>

namespace {

using u64 = std::uint64_t;

struct Work {
    const char* name;
    const char* locale;
};

constexpr Work works[] = {
    {"en_US_grouped", "en_US"}, {"de_grouped", "de"}, {"cs_nbsp", "cs"},
    {"en_IN_indian", "en_IN"},  {"fr_mixed", "fr"},   {"ar_EG_native", "ar_EG"},
};

// value * 10^12 from ICU's decimal string ("-1234.5", "1.2E+3"), truncated
// toward zero like Python's int(Decimal.scaleb(12)), as 128-bit two's complement.
__int128 scaled(const char* s, std::size_t n) {
    bool neg = false;
    std::size_t i = 0;
    if (i < n && (s[i] == '-' || s[i] == '+')) neg = s[i++] == '-';
    __int128 mant = 0;
    int frac = 0;
    bool dot = false;
    for (; i < n && s[i] != 'E' && s[i] != 'e'; ++i) {
        if (s[i] == '.') {
            dot = true;
            continue;
        }
        mant = mant * 10 + (s[i] - '0');
        if (dot) ++frac;
    }
    int exp = 0;
    if (i < n) {
        ++i;
        bool eneg = false;
        if (i < n && (s[i] == '-' || s[i] == '+')) eneg = s[i++] == '-';
        for (; i < n; ++i) exp = exp * 10 + (s[i] - '0');
        if (eneg) exp = -exp;
    }
    int shift = 12 + exp - frac;
    for (; shift > 0; --shift) mant *= 10;
    for (; shift < 0; ++shift) mant /= 10;
    return neg ? -mant : mant;
}

u64 once(const icu::NumberFormat& fmt, const std::vector<std::string>& lines) {
    u64 accepted = 0;
    std::uint32_t digest = 0;
    for (const std::string& line : lines) {
        const icu::UnicodeString u = icu::UnicodeString::fromUTF8(line);
        icu::Formattable f;
        icu::ParsePosition pos(0);
        fmt.parse(u, f, pos);
        if (pos.getErrorIndex() != -1 || pos.getIndex() != u.length()) continue;
        UErrorCode st = U_ZERO_ERROR;
        const icu::StringPiece d = f.getDecimalNumber(st);
        if (U_FAILURE(st)) continue;
        accepted += 1;
        digest += static_cast<std::uint32_t>(static_cast<unsigned __int128>(scaled(d.data(), d.size())));
    }
    return (static_cast<u64>(digest) << 32) | accepted;
}

} // namespace

int main(int argc, char** argv) {
    if (argc != 3) {
        std::fprintf(stderr, "usage: %s <work dir> <workload>\n", argv[0]);
        return 2;
    }
    const Work* wk = nullptr;
    for (const Work& w : works)
        if (std::string(argv[2]) == w.name) wk = &w;
    if (wk == nullptr) {
        std::fprintf(stderr, "unknown workload %s\n", argv[2]);
        return 2;
    }
    std::ifstream in(std::string(argv[1]) + "/" + wk->name + ".txt", std::ios::binary);
    std::stringstream ss;
    ss << in.rdbuf();
    std::vector<std::string> lines;
    std::string line;
    while (std::getline(ss, line)) lines.push_back(line);

    UErrorCode st = U_ZERO_ERROR;
    std::unique_ptr<icu::NumberFormat> fmt(icu::NumberFormat::createInstance(icu::Locale(wk->locale), st));
    if (U_FAILURE(st)) {
        std::fprintf(stderr, "createInstance(%s): %s\n", wk->locale, u_errorName(st));
        return 1;
    }
    fmt->setLenient(false);

    using clock = std::chrono::steady_clock;
    u64 sink = 0;
    u64 n = 1;
    for (;;) {
        const auto t = clock::now();
        for (u64 i = 0; i < n; ++i) sink += once(*fmt, lines) & 1;
        if (clock::now() - t > std::chrono::milliseconds(100)) break;
        n *= 2;
    }
    auto best = clock::duration::max();
    u64 result = 0;
    for (int rep = 0; rep < 5; ++rep) {
        const auto t = clock::now();
        for (u64 i = 0; i < n; ++i) result = once(*fmt, lines);
        best = std::min(best, clock::now() - t);
    }
    if (sink == ~0ULL) std::fputc(' ', stderr);
    const double ns = static_cast<double>(std::chrono::duration_cast<std::chrono::nanoseconds>(best).count()) / n;
    std::fprintf(stderr, "icu %s\n", U_ICU_VERSION);
    std::printf("%s\t%.1f\t%llu\n", wk->name, ns, static_cast<unsigned long long>(result));
    return 0;
}

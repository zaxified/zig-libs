pragma circom 2.0.0;
// Domain-size boundary for phase2.newZkey: rows = constraints + public + 1.
// N = 6 gives 6 + 1 + 1 = 8 rows (exactly 2^3); N = 7 gives 9 (one over).
template Chain(N) {
  signal input x; signal input y;
  signal t[N];
  t[0] <== x*y;
  for (var i = 1; i < N; i++) t[i] <== t[i-1]*y;
}

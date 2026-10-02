pragma circom 2.0.0;
// A squaring chain with a linear tail: every constraint has a nontrivial
// constant, and three public signals.
template Big(N) {
  signal input x; signal input y; signal input k;
  signal output out;
  signal t[N];
  t[0] <== x*y;
  for (var i = 1; i < N; i++) t[i] <== t[i-1]*t[i-1] + i*k + 7;
  out <== t[N-1];
}
component main {public [x, k]} = Big(10000);

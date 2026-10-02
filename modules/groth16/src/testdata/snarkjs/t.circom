pragma circom 2.0.0;
template T() {
  signal input a; signal input b; signal input c;
  signal output out;
  signal t;
  t <== a*b;
  out <== t*c + a;
}
component main {public [a]} = T();

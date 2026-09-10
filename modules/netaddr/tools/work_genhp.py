import random,sys
random.seed(int(sys.argv[1])); N=int(sys.argv[2])
out=["hostport"]
FIX=["[::1]:80","::1:80","2001:db8::1:443","a:b:c","1:2:3","host:80:90",":80","[]:80","[::1]:","x:1:2",
     "1.2.3.4:80","[fe80::1%eth0]:22","::1:1","0:1","a:0:1","1:1","::","[::]:0"]
out+=FIX
alpha="0123456789abcdef:.[]%- "
while len(out)<N:
    n=random.randint(0,24)
    out.append("".join(random.choice(alpha) for _ in range(n)))
sys.stdout.write("\n".join(out)+"\n")

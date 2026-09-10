import random,sys,ipaddress
random.seed(int(sys.argv[1])); N=int(sys.argv[2])
lines=["sum"]; exp=[]
def mk(bits):
    style=random.random()
    M=(1<<bits)-1
    if style<0.25:
        a=random.getrandbits(bits); b=random.getrandbits(bits)
    elif style<0.45:
        a=random.getrandbits(bits); b=min(M,a+random.getrandbits(random.randint(0,bits)))
    elif style<0.60:
        # awkward: one past an aligned boundary
        h=random.randint(0,bits); base=(random.getrandbits(bits)>>h)<<h
        a=max(0,base-random.randint(0,2)); b=min(M,base+(1<<h)-1+random.randint(0,2))
    elif style<0.72:
        a=random.choice([0,1,2]); b=random.choice([M,M-1,M-2,M//2])
    elif style<0.85:
        # maximally awkward: 1 .. M-1
        a=1; b=M-1
    elif style<0.93:
        a=random.getrandbits(bits); b=a
    else:
        a=0;b=M
    if a>b: a,b=b,a
    return a,b
for i in range(N):
    bits = 32 if i%2==0 else 128
    a,b=mk(bits)
    nb=bits//8
    lines.append(a.to_bytes(nb,'big').hex()+" "+b.to_bytes(nb,'big').hex())
    cls = ipaddress.IPv4Address if bits==32 else ipaddress.IPv6Address
    exp.append(",".join(str(p) for p in ipaddress.summarize_address_range(cls(a),cls(b))))
open(sys.argv[3],'w').write("\n".join(lines)+"\n")
open(sys.argv[4],'w').write("\n".join(exp)+"\n")

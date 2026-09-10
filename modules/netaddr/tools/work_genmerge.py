import random,sys,ipaddress
random.seed(int(sys.argv[1])); N=int(sys.argv[2])
lines=["merge"]; exp=[]
for _ in range(N):
    k=random.randint(1,12)
    v4=[];v6=[];texts=[]
    for _ in range(k):
        if random.random()<0.6:
            bits=random.randint(0,32)
            base=random.getrandbits(32)
            net=ipaddress.IPv4Network((base,bits),strict=False)
            # feed netaddr the UNMASKED address on purpose (host bits tolerated)
            a=ipaddress.IPv4Address(base)
            texts.append(f"{a}/{bits}"); v4.append(net)
        else:
            bits=random.randint(0,128)
            base=random.getrandbits(128)
            net=ipaddress.IPv6Network((base,bits),strict=False)
            a=ipaddress.IPv6Address(base)
            texts.append(f"{a}/{bits}"); v6.append(net)
    lines.append(",".join(texts))
    out=[str(x) for x in ipaddress.collapse_addresses(v4)]+[str(x) for x in ipaddress.collapse_addresses(v6)]
    exp.append(",".join(out))
open(sys.argv[3],'w').write("\n".join(lines)+"\n")
open(sys.argv[4],'w').write("\n".join(exp)+"\n")

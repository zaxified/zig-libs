import ipaddress, sys, collections
corpus=open(sys.argv[1],'rb').read().split(b'\n')[1:]
zig=open(sys.argv[2],'rb').read().split(b'\n')
diffs=collections.defaultdict(list)
n=0
for i,line in enumerate(corpus):
    if i>=len(zig): break
    s=line.decode('latin-1')
    z=zig[i].decode('latin-1')
    try:
        a=ipaddress.ip_address(s)
        p=('4' if a.version==4 else '6')+':'+a.packed.hex()
    except Exception:
        p='-'
    zp = z if z=='-' else ':'.join(z.split(':')[:2])
    n+=1
    if zp!=p:
        key=(p=='-', z=='-')
        if len(diffs[key])<40000: diffs[key].append((s,z,p))
print("compared",n)
for k,v in diffs.items():
    label = "PY-reject ZIG-accept" if k[0] else ("ZIG-reject PY-accept" if k[1] else "BOTH-accept DIFFERENT-VALUE")
    print("===",label,len(v))
    for s,z,p in v[:25]:
        print("   ",repr(s),"zig=",z,"py=",p)

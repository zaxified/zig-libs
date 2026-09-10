import ipaddress, socket, sys, collections
corpus=open(sys.argv[1],'rb').read().split(b'\n')[1:]
zig=open(sys.argv[2],'rb').read().split(b'\n')
cats=collections.Counter(); ex=collections.defaultdict(list)
def pton(s):
    for fam,tag in ((socket.AF_INET,'4'),(socket.AF_INET6,'6')):
        try:
            return tag+':'+socket.inet_pton(fam,s).hex()
        except Exception: pass
    return '-'
n=0
for i,line in enumerate(corpus):
    if i>=len(zig): break
    s=line.decode('latin-1'); z=zig[i].decode('latin-1')
    n+=1
    try:
        a=ipaddress.ip_address(s); p=('4' if a.version==4 else '6')+':'+a.packed.hex()
    except Exception: p='-'
    zp = z if z=='-' else ':'.join(z.split(':')[:2])
    try: q=pton(s)
    except Exception: q='-'
    if zp!=p:
        c = 'PY-zone' if '%' in s else 'PY-OTHER'
        cats[c]+=1
        if len(ex[c])<30: ex[c].append((s,zp,p))
    if zp!=q:
        c = 'PTON-zone' if '%' in s else 'PTON-OTHER'
        cats[c]+=1
        if len(ex[c])<30: ex[c].append((s,zp,q))
print("compared",n,cats)
for c in ('PY-OTHER','PTON-OTHER'):
    for e in ex[c][:30]: print(c,repr(e[0]),'zig=',e[1],'oracle=',e[2])

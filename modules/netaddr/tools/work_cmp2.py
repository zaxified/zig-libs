import ipaddress, sys, collections
corpus=open(sys.argv[1],'rb').read().split(b'\n')[1:]
zig=open(sys.argv[2],'rb').read().split(b'\n')
cats=collections.Counter(); ex=collections.defaultdict(list)
for i,line in enumerate(corpus):
    if i>=len(zig): break
    s=line.decode('latin-1'); z=zig[i].decode('latin-1')
    try:
        a=ipaddress.ip_address(s); p=('4' if a.version==4 else '6')+':'+a.packed.hex()
    except Exception: p='-'
    zp = z if z=='-' else ':'.join(z.split(':')[:2])
    if zp==p: continue
    if '%' in s: c='zone'
    elif s!=s.strip(): c='whitespace'
    else: c='OTHER'
    cats[c]+=1
    if len(ex[c])<40: ex[c].append((s,z,p))
print(cats)
for c in ex:
    if c=='OTHER' or c=='whitespace':
        for e in ex[c][:40]: print(c,repr(e[0]),'zig=',e[1],'py=',e[2])

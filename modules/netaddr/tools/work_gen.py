import random, sys
random.seed(int(sys.argv[1]) if len(sys.argv)>1 else 1)
N = int(sys.argv[2]) if len(sys.argv)>2 else 200000
out=[]
HEX="0123456789abcdefABCDEF"
def grp():
    r=random.random()
    if r<0.55: return format(random.getrandbits(16),'x')
    if r<0.70: return format(random.getrandbits(16),'04x')
    if r<0.80: return "0"*random.randint(1,4)+format(random.getrandbits(8),'x')
    if r<0.9:  return "".join(random.choice(HEX) for _ in range(random.randint(1,5)))
    return random.choice(["0","00","000","0000","00000","ffff","FFFF","g","1g","","fFfF"])
def v4():
    r=random.random()
    def oct_():
        s=random.random()
        if s<0.6: return str(random.randint(0,255))
        if s<0.75: return str(random.randint(0,999))
        if s<0.9: return "0"*random.randint(1,2)+str(random.randint(0,99))
        return random.choice(["","0x1","1a","-1","+1"," 1","256","255"])
    n=random.choice([3,4,4,4,4,5,2])
    return ".".join(oct_() for _ in range(n))
def make():
    r=random.random()
    if r<0.30:
        n=random.randint(0,10)
        parts=[grp() for _ in range(n)]
        s=":".join(parts)
    elif r<0.70:
        a=random.randint(0,5); b=random.randint(0,5)
        s=":".join(grp() for _ in range(a))+"::"+":".join(grp() for _ in range(b))
    elif r<0.80:
        a=random.randint(0,6)
        s=":".join(grp() for _ in range(a))+("::" if random.random()<0.6 else ":")+v4()
    elif r<0.88:
        s=v4()
    elif r<0.93:
        n=random.randint(0,4)
        s=":".join(grp() for _ in range(n))+"::"+":".join(grp() for _ in range(random.randint(0,2)))+"::"+":".join(grp() for _ in range(random.randint(0,2)))
    else:
        alpha="0123456789abcdefABCDEF:.%[]xX -+"
        s="".join(random.choice(alpha) for _ in range(random.randint(0,50)))
    if random.random()<0.04: s="%"+s
    if random.random()<0.04: s=s+"%eth0"
    if random.random()<0.03: s=s+"%"
    if random.random()<0.03: s=" "+s
    if random.random()<0.03: s=s+" "
    return s
seen=set()
FIXED=["::","::1","1::","::ffff:192.0.2.1","64:ff9b::192.0.2.33","1::2:3:4:5:6:7:8",
"1:2:3:4:5:6:7:8","0001:0002::","00001::","010.0.0.1","::ffff:192.0.2.1.5","::192.0.2.256",
"fe80::1%eth0","fe80::1%","fe80::1%0","::%eth0","FE80::1","1:2:3:4:5:6:7::","::1:2:3:4:5:6:7",
"1:2:3:4:5:6:7:8:9","::ffff:0:0","::ffff:0:0:0","0:0:0:0:0:ffff:1.2.3.4","0:0:0:0:0:0:1.2.3.4",
"::0.0.0.0","::255.255.255.255","1.2.3.4","1.2.3","1.2.3.4.5","0.0.0.0","255.255.255.255",
"256.0.0.1","1.2.3.04","01.2.3.4","","::::","2001:db8::1","2001:DB8::1",
"1:2:3:4:5:6:1.2.3.4","1:2:3:4:5:6:7:1.2.3.4","::1.2.3.4:5","1.2.3.4::","::ffff:1.2.3.4.5",
"a"*45,"1"*46,"0:0:0:0:0:0:0:0","::0","0::","0::0","::ffff:ffff:1.2.3.4",
"::ffff:127.0.0.1","::127.0.0.1","::a.b.c.d","::1%","x::1","1::%eth0"]
for s in FIXED: out.append(s)
while len(out)<N:
    s=make()
    if "\n" in s: continue
    out.append(s)
sys.stdout.write("ip\n"+"\n".join(out)+"\n")

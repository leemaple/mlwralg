"""Clear-vector oracle for P03 Algorithms 2/3, including every auxiliary slot.

This is a mathematical transform test, not evidence of encrypted bootstrapping.
It checks the repeated layout, conjugation, block sums and final fill separately.
"""
import cmath
import json
import math


def rotate(x, step):
    step %= len(x)
    return x[step:]+x[:step]


def transform(x, m, inverse):
    full=len(x);block=full//(2*m)
    powers=[pow(5,j,4*m) for j in range(m)]
    y=[]
    for pos,value in enumerate(x):
        coefficient=pos//block
        angle=2*math.pi*((coefficient*powers[pos%m])%(4*m))/(4*m)
        mask=cmath.exp((1 if inverse else -1)*1j*angle)
        y.append(value*mask if not inverse or pos%block<block//2 else 0j)
    steps=[block*(1<<j) for j in range((2*m).bit_length()-1)] if inverse else [1<<j for j in range(m.bit_length()-1)]
    for step in steps:
        y=[a+b for a,b in zip(y,rotate(y,step))]
    return [a+b for a,b in zip(y,rotate(y,block//2))] if inverse else [z+z.conjugate() for z in y]


worst=0.;checks=0
for N,m in [(128,4),(512,8),(8192,8),(8192,32),(16384,32)]:
    assert 8*m*m<=N
    for family in range(3):
        x=[complex(math.sin(1.17*j+.21*family),math.cos(.71*j-.17*family)) for j in range(m)]
        if family==1:x=[complex(1 if j%2 else -1,0) for j in range(m)]
        if family==2:x=[complex(j==m-1,0) for j in range(m)]
        full=[x[j%m]/(2*m) for j in range(N//2)]
        cts=transform(full,m,False)
        coefficients=[sum((x[j]*cmath.exp(-2j*math.pi*((pow(5,j,4*m)*c)%(4*m))/(4*m))).real for j in range(m))/m for c in range(2*m)]
        block=N//(4*m)
        # The final m-1 entries of each coefficient block contain cross-block
        # sums, not that block's coefficient. StC discards them. Validate every
        # retained position, and bound ALL auxiliary positions instead of
        # falsely asserting that the entire intermediate block is constant.
        errors=[abs(cts[pos]-coefficients[pos//block]) for pos in range(N//2) if pos%block<block//2]
        assert max(abs(z) for z in cts)<=max(abs(z) for z in x)+1e-12
        stc=transform(cts,m,True)
        errors += [abs(value-x[pos%m]) for pos,value in enumerate(stc)]
        assert max(errors)<1e-12,(N,m,family,max(errors))
        worst=max(worst,max(errors));checks+=len(errors)+len(cts)
print(json.dumps({'class':'clear_transform_oracle','checks':checks,'max_error':worst,'passed':True}))

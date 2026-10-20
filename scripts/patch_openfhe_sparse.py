"""Apply a narrowly scoped P03 transform port to the exact pinned OpenFHE blob.

Never modifies the original dependency automatically. Call on a separate checkout.
No external patch is executed; all replacements are count-checked below.
"""
import argparse
import hashlib
from pathlib import Path

EXPECTED = '79f05cf473ecb3d93bb4775b70a69b2991026a9426f7e586070d5e193237aab7'
parser=argparse.ArgumentParser()
parser.add_argument('source',type=Path)
args=parser.parse_args()
target=args.source/'src/pke/lib/scheme/ckksrns/ckksrns-fhe.cpp'
original=target.read_bytes()
if hashlib.sha256(original).hexdigest()!=EXPECTED:
    raise SystemExit('Refusing patch: original ckksrns-fhe.cpp digest differs from pinned v1.6.1')
text=original.decode()
helper=(Path(__file__).resolve().parents[1]/'patches/openfhe-p03-small.inc').read_text()

def replace_once(old,new):
    global text
    if text.count(old)!=1:
        raise SystemExit(f'Expected one source anchor, found {text.count(old)}: {old[:100]}')
    text=text.replace(old,new,1)

replace_once('void FHECKKSRNS::EvalBootstrapSetup(',helper+'\nvoid FHECKKSRNS::EvalBootstrapSetup(')
replace_once('auto evalKeys = algo->EvalAtIndexKeyGen(privateKey, FindBootstrapRotationIndices(slots, M));',
             'auto evalKeys = algo->EvalAtIndexKeyGen(privateKey, MLWRP03Active(cc) ? MLWRP03Rotations(M/2,FindBootstrapRotationIndices(slots,M)) : FindBootstrapRotationIndices(slots, M));')
# Scope transform anchors to the sparse branch of regular EvalBootstrap only.
start=text.index('Ciphertext<DCRTPoly> FHECKKSRNS::EvalBootstrap(')
end=text.index('Ciphertext<DCRTPoly> FHECKKSRNS::EvalBootstrapStCFirst(',start)
prefix,body,suffix=text[:start],text[start:end],text[end:]
marker='        EvalPartialSumInPlace(raised, slots);'
if body.count(marker)!=1:raise SystemExit('Sparse PartialSum anchor is not unique')
before,sparse=body.split(marker,1)
old='''        auto ctxtEnc = (isLTBootstrap) ? EvalLinearTransform(p.m_U0hatTPre, raised) :
                                         EvalCoeffsToSlots(p.m_U0hatTPreFFT, raised);'''
new='''        const bool mlwrSparse=MLWRP03Active(cc);
        if(mlwrSparse && (!isLTBootstrap || compositeDegree!=1))
            OPENFHE_THROW("P03 port requires level budgets {1,1} and composite degree 1.");
        const double mlwrPre=qDouble/std::exp2(std::round(std::log2(qDouble)));
        auto ctxtEnc = mlwrSparse ? MLWRP03CtS(raised,slots,mlwrPre/GetModRaiseOverflowBound(cryptoParams,K_UNIFORM)) :
            (isLTBootstrap ? EvalLinearTransform(p.m_U0hatTPre,raised) : EvalCoeffsToSlots(p.m_U0hatTPreFFT,raised));'''
if sparse.count(old)!=1:raise SystemExit('Sparse CtS anchor is not unique')
sparse=sparse.replace(old,new,1)
old='''        ctxtDec = (isLTBootstrap) ? EvalLinearTransform(p.m_U0Pre, ctxtEnc) : EvalSlotsToCoeffs(p.m_U0PreFFT, ctxtEnc);
        cc->EvalAddInPlaceNoCheck(ctxtDec, cc->EvalRotate(ctxtDec, slots));'''
new='''        if(mlwrSparse) ctxtDec=MLWRP03StC(ctxtEnc,slots,1.0/mlwrPre);
        else {
            ctxtDec = (isLTBootstrap) ? EvalLinearTransform(p.m_U0Pre, ctxtEnc) : EvalSlotsToCoeffs(p.m_U0PreFFT, ctxtEnc);
            cc->EvalAddInPlaceNoCheck(ctxtDec, cc->EvalRotate(ctxtDec, slots));
        }'''
if sparse.count(old)!=1:raise SystemExit('Sparse StC anchor is not unique')
sparse=sparse.replace(old,new,1)
text=prefix+before+marker+sparse+suffix
target.write_text(text)
print(hashlib.sha256(text.encode()).hexdigest(),target)

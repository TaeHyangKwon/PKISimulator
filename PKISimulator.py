from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import pickle


def genCertificate(myPubKey, CAPrivKey):
    #인증서 만드는 함수
    S_h = SHA256.new(str(myPubKey.export_key('PEM')).encode('utf-8'))
    S = pkcs1_15.new(CAPrivKey).sign(S_h)
    return [myPubKey.export_key('PEM'), S]


def veriCetificate(aCertificate, CACertificate):
    try:
        print("검증 시작")
        h = SHA256.new(str(aCertificate[0]).encode('utf-8'))
        pkcs1_15.new(RSA.import_key(CACertificate[0])).verify(h, aCertificate[1])
        return True
    except(ValueError, TypeError):
        return False


#a
CAPrivKey = RSA.generate(2048)
f = open('CAPrivKey.pem', 'wb')
f.write(CAPrivKey.export_key('PEM',  passphrase="!@#$"))
f.close()

#b
f = open('CAPubKey.pem', 'wb')
f.write(CAPrivKey.public_key().export_key('PEM'))
f.close()

#c
f = open('CAPubKey.pem', 'r')
CA_pub = RSA.import_key(f.read())
f.close()
f = open('CAPrivKey.pem', 'r')
CAPrivKey = RSA.import_key(f.read(), passphrase="!@#$")
f.close()
root_c = genCertificate(CA_pub, CAPrivKey)
f = open('CACertCA.plk', 'wb')
pickle.dump(root_c, f)
f.close()

#d
BobPrivKey = RSA.generate(2048)
f = open('BobPrivKey.pem', 'wb')
f.write(BobPrivKey.export_key('PEM', passphrase="!@#$"))
f.close()

#e
f = open('BobPubKey.pem', 'wb')
f.write(BobPrivKey.public_key().export_key('PEM'))
f.close()

#f
f = open('BobPubKey.pem', 'r')
Bob_pub = RSA.import_key(f.read())
f.close()
S_Bob_c = genCertificate(Bob_pub, CAPrivKey)
f = open('BobCertCA.plk', 'wb')
pickle.dump(S_Bob_c, f)
f.close()

#g
m = "I bought 100 doge coins."
h = SHA256.new(m.encode('utf-8'))
f = open('BobPrivKey.pem', 'r')
BobPrivKey = RSA.import_key(f.read(), passphrase="!@#$")
f.close()
s = pkcs1_15.new(BobPrivKey).sign(h)
print("메시지 서명 S : ", s)
print("메시지 m : ", m)
print("공개키 인증서 [Bob_pub, S_Bob_CA] : ", S_Bob_c)

#h
f = open('BobCertCA.plk', 'rb')
read_bob = pickle.load(f)
f.close()
Alice_receive = [m, s, read_bob]

#i
f = open('CACertCA.plk', 'rb')
read_ca = pickle.load(f)
f.close()

#j
if veriCetificate(root_c, read_ca):
    print("The signature is valid")
else:
    print("The signature is not valid")
    exit()

#k
if veriCetificate(Alice_receive[2], read_ca):
    print("The signature is valid")
else:
    print("The signature is not valid")
    exit()

#l
try:
    pkcs1_15.new(RSA.import_key(Alice_receive[2][0])).verify(SHA256.new(Alice_receive[0].encode('utf-8')), Alice_receive[1])
    print("The signature is valid")
except(ValueError, TypeError):
    print("The signature is not valid")

#m
print("Good job. Well done!")

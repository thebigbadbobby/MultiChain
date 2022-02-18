import ecdsa as ec
import secrets
import binascii
def verify(signature,transaction, verifying_key):
        verifier=ec.VerifyingKey.from_string(bytes.fromhex(binascii.hexlify(verifying_key.to_string()).decode('utf-8')), curve=ec.SECP256k1)
        try:
            return verifier.verify(signature, transaction.encode('utf-8'))
        except:
            return False
class Node():
    def __init__(self):
        self.secret_key = ec.SigningKey.generate(curve=ec.SECP256k1) 
        self.verifying_key= self.secret_key.get_verifying_key()
    def sign(self,transaction):
        return self.secret_key.sign(transaction.encode('utf-8'))
    def getVerifyingKey(self):
        return self.verifying_key
class ThresholdSignatureAddress:
    def __init__(self,verifying_keys, num_required):
        self.publicaddress = secrets.token_hex(32)
        self.verifying_keys = verifying_keys
        self.num_required=num_required
        self.transactions=[]
    def val(self, signatures, transaction, verifying_keys):
        # print(verifying_keys)
        # print(self.verifying_keys)
        if len(signatures)!=len(verifying_keys):
            return False
        else:
            for i in range(0,len(verifying_keys)):
                if not (verifying_keys[i] in self.verifying_keys):
                    return False
                if not verify(signatures[i], transaction, verifying_keys[i]):
                    return False
            if len(verifying_keys)>=self.num_required:
                return True
        return False
    
# secret_key = ec.SigningKey.generate(curve=ec.SECP256k1) 
# secret_key_PEM=secret_key.to_pem()
# print(secret_key_PEM)
# signature=secret_key.sign(b"GANGSTERS NARCOS AND GOONS")
# print(signature)
# verifying_key = secret_key.get_verifying_key()
# print(verifying_key)
# signature=secret_key.sign(b"eeeekansas")
# verifying_key = secret_key.get_verifying_key()
# print(verifying_key)

node1= Node()
node2= Node()
address=ThresholdSignatureAddress([node1.getVerifyingKey(),node2.getVerifyingKey()],2)
signature1=node1.sign("test transaction")
signature2=node2.sign("test transaction")
print(address.val([signature1, signature2],"test transaction", [node1.getVerifyingKey(), node2.getVerifyingKey()]))
print(address.val([signature1],"test transaction", [node1.getVerifyingKey()]))

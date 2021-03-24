from hashlib import sha256
from nacl import pwhash, secret, utils
import base64
import os

bletters = ['Ç','ü','é','â','ä','à','å','ç','ê','ë','è','ï','î','ì','Ä','Å','É','æ','Æ','ô','ö','ò','û','ù','ÿ','Ö','Ü','ø','£','Ø',]
dlim = 'ø'
hnum = ['è','Ä','É','æ','Æ','ô','ù','ÿ','Ö','Ü','ü','ë','£','ì','Ø','é','ä','ò']

# salt = utils.random(pwhash.argon2i.SALTBYTES)
salt = b'\xee\xaf}\xb2Gn\xbb\xb7\xd7B2\xdb\x89\xef?\xb3'

def calcPerms(n):
    H = int(sha256(str(n).encode('utf-8')).hexdigest(),16)
    ret = [[],[],[]]
    ranges = [list(range(n)),list(range(n)),list(range(n))]
    for j in range(3):
        for i in range(n):
            ret[j].append(ranges[j].pop(H%(n-i)))
            H -= (n-i)
    return tuple(ret)

def hencode(n):
    digits = 1
    ret = ''
    while n//17**digits: digits += 1
    for d in range(digits,0,-1):
        ret += hnum[(n//17**(d-1))%17]
    return ret

def hdecode(h):
    ret = 0
    for d in range(len(h)):
        ret += hnum.index(h[d]) * 17**(len(h)-1-d)
    return ret

def get_salt():
    if not os.path.exists('salt.bin'):
        with open('salt.bin','wb') as f:
            salt = utils.random(pwhash.argon2i.SALTBYTES*4)
            f.write(salt)
    with open('salt.bin','rb') as f:
        f = f.read()
    slen = pwhash.argon2i.SALTBYTES
    return [f[:slen],f[slen:2*slen],f[2*slen:3*slen],f[3*slen:]]

from getpass import getpass
def get_boxes(salt,algo=pwhash.argon2i.kdf):
    if not isinstance(salt,list): salt = [salt]*4
    create_box = lambda x : secret.SecretBox(algo(secret.SecretBox.KEY_SIZE,x[0].encode('utf-8'),x[1]))
    while True:
        password = getpass()
        if len(password) >= 20 and len(password) <= 32: break
        print('Password length must be between 20 and 32 characters')
        # TODO: More password conditions
    plen = len(password)//4
    return list(map(create_box,zip([password[3*plen:],password[:plen],password[plen:2*plen],password[2*plen:3*plen]],salt)))

def convert_mid(a):
    rd = [('\\r','\r'),
          ('\\n','\n'),
          ('\\t','\t'),
          ("\\\'",'\'')]
    a = a.split('\\\\')
    for k,v in rd:
        for ai in range(len(a)):
            a[ai] = a[ai].replace(k,v)
    aray = []

    for ai in range(len(a)):
        X = a[ai].split('\\x')
        x = X.pop(0)
        aray.append('')
        for y in x:
            aray[-1] += chr(ord(y))
        for x in X:
            aray[-1] += chr(int(x[:2],16))
            for y in x[2:]:
                aray[-1] += chr(ord(y))

    aray = '\\'.join(aray)

    return utils.EncryptedMessage(aray.encode('ISO-8859-1'))

def download_from_file(path):
    names, infos, passwords = [], [], []
    with open(path,'r') as f:
        f = ''.join(f.readlines())
    records = f.split('-------------------------------------------------\n')
    for r in records:
        lines = r.split('\n')
        if r == '' or lines[0] == '': continue
        name = lines.pop(0)
        names.append(name)
        infos.append({})
        notes = ''
        for l in lines:
            if l == '': continue
            if ':' in l:
                k,v = l[:l.index(':')], l[l.index(':')+1:].strip()
                infos[-1].update({k.lower():v})
            else:
                notes += ' '+l.strip()
        if notes:
            infos[-1].update({'notes':notes.strip()})
        if 'password' in infos[-1]:
            passwords.append(infos[-1].pop('password'))
        else:
            passwords.append('')
    return names, infos, passwords
    # after calling this, encrypt and reorder infos and passwords
        
def encrypt_lists(names,infos,passwords,path,boxes):
    n = len(names)
    dlim = 'ø'
    encrypt_part = hencode(n)

    permute = lambda x, y   : [x[i] for i in calcPerms(len(x))[y]]
    dictstr = lambda x      : ','.join([k+':'+v for k,v in x.items()])
    encrypt = lambda x, bidx : str(boxes[bidx].encrypt(x.encode('utf-8')))[2:][:-1]

    for name in permute(names,0):         encrypt_part += dlim + encrypt(name,          1)
    for info in permute(infos,1):         encrypt_part += dlim + encrypt(dictstr(info), 2)
    for password in permute(passwords,2): encrypt_part += dlim + encrypt(password,      3)

    encrypt_final = boxes[0].encrypt(encrypt_part.encode('utf-8'))
    with open(os.path.join(os.path.dirname(os.path.abspath(__file__)),path.split('/')[-1]+'.crypt'),'w') as f:
        f.write(base64.b64encode(encrypt_final).decode('ascii'))

def decrypt_path(path,boxes):
    with open(path,'r') as f:
        fullcrypt = base64.b64decode(f.read())

    midcrypt = boxes[0].decrypt(fullcrypt).decode('utf-8').split(dlim)
    n = hdecode(midcrypt.pop(0))
    perms = calcPerms(n)

    ncrypt = midcrypt[:n]
    icrypt = midcrypt[n:2*n]
    pcrypt = midcrypt[2*n:]

    names, infos, passwords = ['']*n,['']*n,['']*n
    
    strdict = lambda x      : dict([(p.split(':')[0],':'.join(p.split(':')[1:])) for p in x.split(',') if p.split(':')[0]])
    decrypt = lambda x, bidx : boxes[bidx].decrypt(convert_mid(x)).decode('utf-8')

    for ni,ii,pi in zip(*perms):
        names[ni]     =         decrypt(ncrypt.pop(0), 1)
        infos[ii]     = strdict(decrypt(icrypt.pop(0), 2))
        passwords[pi] =         decrypt(pcrypt.pop(0), 3)

    return names, infos, passwords

def convert_file(ipath,opath):
    n, i, p  = download_from_file(ipath)
    boxes = get_boxes(get_salt())
    encrypt_lists(n,i,p,opath,boxes)
    no,io,po = decrypt_path(opath+'.crypt',boxes)
    print('File Conversion:','Sucessful' if all([n==no,i==io,p==po]) else 'Failed')

def check_conversion(ipath,opath):
    n, i, p  = download_from_file(ipath)
    boxes = get_boxes(get_salt())
    no,io,po = decrypt_path(opath+'.crypt',boxes)
    print('File Conversion:','Sucessful' if all([n==no,i==io,p==po]) else 'Failed')



# Temp
def processNames():
    pass

def getLists(path,key):
    #return [ordered and decrypted name sets],[],[]
    pass

def search(name):
    pass

def fetch(nidx):
    pass

def fetchup(nidx):
    pass

def edit(nidx,infos):
    ns = remove(nidx)
    # add ns to infos
    add(infos)

def add(info):
    #order encrypted lists
    #append name set
    #if defaults params don't exist initialize
    #encrypt infos 
    #append infos 
    #reorder encrypted lists
    pass

def remove(info):
    #order encrypted lists
    #pop name set
    #remove infos 
    #reorder encrypted lists
    #return name set
    pass

def main():
    # Pull Keys
    # Check Password
    # Load file
    # Query Loop
        # Search
            # Show
            # Show Password
        # Edit
        # Add
        # Remove
    # Save
    convert_file('watch.txt','watch')
    #check_conversion('watch.txt','watch')

if __name__ == '__main__': main()

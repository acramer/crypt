from hashlib import sha256
from nacl import pwhash, secret, utils
import base64
import os

bletters = ['Ç','ü','é','â','ä','à','å','ç','ê','ë','è','ï','î','ì','Ä','Å','É','æ','Æ','ô','ö','ò','û','ù','ÿ','Ö','Ü','ø','£','Ø',]
dlim = 'ø'
hnum = ['è','Ä','É','æ','Æ','ô','ù','ÿ','Ö','Ü','ü','ë','£','ì','Ø','é','ä','ò']

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
from time import time
def get_boxes(salt,algo=pwhash.argon2i.kdf,ttl=100):
    if get_boxes.boxes is not None and abs(time()-get_boxes.box_time) < get_boxes.ttl:
        return get_boxes.boxes
    else:
        get_boxes.boxes = None
    get_boxes.box_time = time()
    get_boxes.ttl = ttl

    if not isinstance(salt,list): salt = [salt]*4
    create_box = lambda x : secret.SecretBox(algo(secret.SecretBox.KEY_SIZE,x[0].encode('utf-8'),x[1]))
    while True:
        password = getpass()
        if len(password) >= 20 and len(password) <= 32: break
        print('Password length must be between 20 and 32 characters')
        # TODO: More password conditions
    plen = len(password)//4
    get_boxes.boxes = list(map(create_box,zip([password[3*plen:],password[:plen],password[plen:2*plen],password[2*plen:3*plen]],salt)))
    return get_boxes.boxes

get_boxes.box_time = None
get_boxes.boxes = None
get_boxes.ttl = None

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
    # dlim = 'ø'
    encrypt_part = hencode(n)

    permute = lambda x, y    : [x[i] for i in calcPerms(len(x))[y]]
    dictstr = lambda x       : ','.join([k+':'+v for k,v in x.items()])
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



def search(name, names, threshold=-1, num=10):
    # Tokenize w1
    # Tokenize w2
    # for each word in w1
    #   for each word in w2
    #     compare lev of words
    #   take the minimum lev
    # Compute the average lev of w1 words
    def lev(w1,w2):
        cmat = [[0]*(len(w2)+1) for _ in range(len(w1)+1)]
        for r in range(1,len(w1)+1): cmat[r][0] = r
        for c in range(1,len(w2)+1): cmat[0][c] = c
    
        for r in range(len(w1)):
            for c in range(len(w2)):
                cmat[r+1][c+1] = min([cmat[r+1][c]+1, cmat[r][c+1]+1, cmat[r][c]+(0 if w1[r]==w2[c] else 1)])
        return cmat[-1][-1]
    return list(map(lambda x:x[0],filter(lambda x:x[1]<threshold or threshold==-1, sorted([(i,lev(name,n)) for i,n in enumerate(names)],key=lambda x:x[1]))))[:num]

def populate(cfile):
    boxes = get_boxes(get_salt())

    with open(cfile,'r') as f:
        fullcrypt = base64.b64decode(f.read())

    populate.midcrypt = boxes[0].decrypt(fullcrypt).decode('utf-8').split(dlim)
    midcrypt = populate.midcrypt[:]
    n = hdecode(midcrypt.pop(0))
    nis,_,_ = calcPerms(n)

    ncrypt = midcrypt[:n]
    names = ['']*n
    
    decrypt = lambda x, bidx : boxes[bidx].decrypt(convert_mid(x)).decode('utf-8')

    for i, ni in enumerate(nis):
        names[ni] = decrypt(ncrypt[i], 1)

    return names
populate.midcrypt = []


def getInfo(nidx):
    boxes = get_boxes(get_salt())

    midcrypt = populate.midcrypt[:]
    n = hdecode(midcrypt.pop(0))
    nis,iis,_ = calcPerms(n)

    icrypt = midcrypt[n:2*n]
    decrypt = lambda x, bidx : boxes[bidx].decrypt(convert_mid(x)).decode('utf-8')

    return dict(p.split(':') for p in decrypt(icrypt[iis.index(nidx)],2).split(',') if p)


def getPassword(nidx):
    boxes = get_boxes(get_salt())

    midcrypt = populate.midcrypt[:]
    n = hdecode(midcrypt.pop(0))
    nis,_,pis = calcPerms(n)

    pcrypt = midcrypt[2*n:]
    decrypt = lambda x, bidx : boxes[bidx].decrypt(convert_mid(x)).decode('utf-8')

    return decrypt(pcrypt[pis.index(nidx)],3)

def updateName(nidx,name):
    boxes = get_boxes(get_salt())
    midcrypt = populate.midcrypt[:]
    n = hdecode(midcrypt.pop(0))
    idx = calcPerms(n)[0].index(nidx)
    encrypt = lambda x, bidx : str(boxes[bidx].encrypt(x.encode('utf-8')))[2:][:-1]
    populate.midcrypt[1+iidx] = encrypt(name, 1)

def upateInfo(nidx, upInfo):
    boxes = get_boxes(get_salt())
    midcrypt = populate.midcrypt[:]
    n = hdecode(midcrypt.pop(0))
    idx = calcPerms(n)[1].index(nidx)

    dictstr = lambda x       : ','.join([k+':'+v for k,v in x.items()])
    encrypt = lambda x, bidx : str(boxes[bidx].encrypt(x.encode('utf-8')))[2:][:-1]

    newInfo = getInfo(nidx)
    for k,v in upInfo.items():
        if v == '_' and k in newInfo: newInfo.pop(k)
        else: newInfo[k]=v

    populate.midcrypt[n+1+idx] = encrypt(dictstr(newInfo), 2)

def upatePassword(nidx, newPassword):
    boxes = get_boxes(get_salt())
    midcrypt = populate.midcrypt[:]
    n = hdecode(midcrypt.pop(0))
    idx = calcPerms(n)[2].index(nidx)
    encrypt = lambda x, bidx : str(boxes[bidx].encrypt(x.encode('utf-8')))[2:][:-1]
    populate.midcrypt[2*n+1+idx] = encrypt(newPassword, 3)

def addCredentials(name,info='',password=''):
    boxes = get_boxes(get_salt())
    midcrypt = populate.midcrypt[:]
    n = hdecode(midcrypt.pop(0))
    perms = calcPerms(n)

    permute = lambda x, y    : [x[i] for i in calcPerms(len(x))[y]]
    encrypt = lambda x, bidx : str(boxes[bidx].encrypt(x.encode('utf-8')))[2:][:-1]

    ncrypt = midcrypt[:n]
    icrypt = midcrypt[n:2*n]
    pcrypt = midcrypt[2*n:]

    names, infos, passwords = ['']*n,['']*n,['']*n
    
    for ni,ii,pi in zip(*perms):
        names[ni]     = ncrypt.pop(0)
        infos[ii]     = icrypt.pop(0)
        passwords[pi] = pcrypt.pop(0)

    names.append(encrypt(name,1))
    infos.append(encrypt(info,2))
    passwords.append(encrypt(password,3))

    populate.midcrypt = [hencode(n+1)]+permute(names,0)+permute(infos,1)+permute(passwords,2)

def removeCredentials(nidx):
    boxes = get_boxes(get_salt())
    midcrypt = populate.midcrypt[:]
    n = hdecode(midcrypt.pop(0))
    perms = calcPerms(n)

    ncrypt = midcrypt[:n]
    icrypt = midcrypt[n:2*n]
    pcrypt = midcrypt[2*n:]

    names, infos, passwords = ['']*n,['']*n,['']*n
    
    for ni,ii,pi in zip(*perms):
        names[ni]     = ncrypt.pop(0)
        infos[ii]     = icrypt.pop(0)
        passwords[pi] = pcrypt.pop(0)

    names.pop(nidx)
    infos.pop(nidx)
    passwords.pop(nidx)

    permute = lambda x, y    : [x[i] for i in calcPerms(len(x))[y]]
    populate.midcrypt = [hencode(n-1)]+permute(names,0)+permute(infos,1)+permute(passwords,2)


def save(path):
    encrypt_final = get_boxes(get_salt())[0].encrypt(dlim.join(populate.midcrypt).encode('utf-8'))
    with open(os.path.join(os.path.dirname(os.path.abspath(__file__)),path.split('/')[-1]),'w') as f:
        f.write(base64.b64encode(encrypt_final).decode('ascii'))
        print('Saved:',os.path.join(os.path.dirname(os.path.abspath(__file__)),path.split('/')[-1]))

def main(args):
    if args.mode == 'encrypt':
        assert args.rawFile, "must specify a input file with 'encrypt' mode"
        convert_file(args.rawFile, args.cryptFile)
    elif args.mode == 'access':
        names = populate(args.cryptFile)
        while True:
            query_name = input('Name:').strip()
            if query_name == 'quit':
                save(args.cryptFile)
                break
            sindices = search(query_name,names) if query_name else range(len(names))
            snames   = sorted([(si,names[si]) for si in sindices],key=lambda x:x[1])
            if snames:
                print('Found:')
                print(*['('+str(i)+') '+name for i, (si, name) in enumerate(snames)],sep='\n')
            else:
                print('No Names found')
            print('(n) **Create New**')
            print('(q) **New Search**')
            while True:
                sidx = input('Select:').strip()
                if sidx == 'q' or (sidx == 'n' and input('Create New (y/n):').strip() == 'y'): break
                elif sidx.isdigit() and int(sidx) >= 0 and int(sidx) < len(snames):
                    sidx = int(sidx)
                    break
                print('Selection out of range')
            if sidx == 'q': continue
            elif sidx == 'n':
                defaultName = '' if query_name in names else query_name
                newName = input('Name'+(' ('+defaultName+')' if defaultName else '')+':').strip()
                newName = newName if newName else defaultName
                while newName in names and newName == '': 
                    print('Different name needed, cannot be blank and cannot exist already')
                    newName = input('Name'+(' ('+defaultName+')' if defaultName else '')+':').strip()
                    newName = newName if newName else defaultName

                while True:
                    newInfo = input('Info:').strip('{}').strip()
                    if all(map(lambda x:len(x)==2,[x.split(':') for x in newInfo.split(',')])): break
                    print('Invalid Syntax')

                addCredentials(newName,newInfo,input('Password:').strip())
                names.append(newName)
            else:
                print('Selected:',names[snames[sidx][0]])
                while True:
                    print('Pick from the following actions:')
                    print('(0) Deselect')
                    print('(1) Read Infos')
                    print('(2) Read Password')
                    print('(3) Change Name')
                    print('(4) Update Info')
                    print('(5) Change Password')
                    print('(6) Delete')
                    act = int(input('Action:').strip())
                    if act == 0: break
                    elif act == 1:
                        print(*['{} : {}'.format(k,v) for k,v in getInfo(snames[sidx][0]).items()],sep='\n')
                    elif act == 2:
                        print(getPassword(snames[sidx][0]))
                    elif act == 3:
                        defaultName = names[snames[sidx][0]]
                        newName = input('Name ('+defaultName+'):').strip()
                        newName = newName if newName else defaultName
                        while newName in names and newName == '' and newName != defaultName:
                            print('Different name needed, cannot be blank and cannot exist already')
                            newName = input('Name ('+defaultName+'):').strip()
                            newName = newName if newName else defaultName
                        updateName(snames[sidx][0],newName)
                        names[snames[sidx][0]] = newName
                    elif act == 4:
                        while True:
                            inp = [x.split(':') for x in input('New Info:').strip().strip('{}').split(',')]
                            if all(map(lambda x:len(x)==2,inp)): break
                            print('Invalid Syntax')
                        upateInfo(snames[sidx][0],dict(inp))
                        print(*['{} : {}'.format(k,v) for k,v in getInfo(snames[sidx][0]).items()],sep='\n')
                    elif act == 5:
                        upatePassword(snames[sidx][0], input('New Password:').strip())
                    elif act == 6:
                        removeCredentials(snames[sidx][0])
                        names.pop(snames[sidx][0])
                        break

    # TODO: Test Recovery
    #     TODO: Breakdown
    # TODO: Change Chars and Dlim
    #     TODO: Breakdown
    # TODO: Pull and push to private
    #     TODO: Breakdown
    # TODO: Implent Command Line
    #     TODO: Breakdown
    # TODO: Automate Pull/Push
    #     TODO: Breakdown
    # TODO: Rewrite in c and shell
    #     TODO: Breakdown
    # TODO: Reimplent Command Line
    #     TODO: Breakdown
    # TODO: Credential Time Alive Tracking and Reset Reminder
    #     TODO: Breakdown
    # TODO: Reimplent Command Line
    #     TODO: Breakdown

import sys
import argparse
if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument(metavar='MODE',
                            dest='mode',
                            type=str,
                            nargs='?',
                            choices=['encrypt','access'],
                            default='access')
    parser.add_argument(metavar='FILE',
                            dest='rawFile',
                            type=str,
                            nargs='?',
                            default=None)
    parser.add_argument('-S', '--salt_file',
                            dest='saltFile',
                            type=str,
                            default='salt.bin')
    parser.add_argument('-c', '--crypt_file',
                            dest='cryptFile',
                            type=str,
                            default='watch.crypt')
    main(parser.parse_args())

def levinshtien_distance(w1,w2):
    cmat = [[0]*(len(w2)+1) for _ in range(len(w1)+1)]
    for r in range(1,len(w1)+1): cmat[r][0] = r
    for c in range(1,len(w2)+1): cmat[0][c] = c

    print_lev_mat(cmat,w1,w2)

    for r in range(len(w1)):
        for c in range(len(w2)):
            cmat[r+1][c+1] = min([cmat[r+1][c]+1, cmat[r][c+1]+1, cmat[r][c]+(1 if w1[r]==w2[c] else 0)])
    print('--------------------------------')
    print_lev_mat(cmat,w1,w2)

    return cmat[-1][-1]
    
def print_lev_mat(mat,w1,w2):
    print(*[' '.join(list(map(str,r))) for r in [[' ','#']+list(w2)]+list(map(lambda x:[x[0]]+x[1],zip('#'+w1,mat)))],sep='\n')


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

def main(w1='', w2='', *args):
    print(levinshtien_distance(w1,w2))

from sys import argv
if __name__ == '__main__': main(*argv[1:])

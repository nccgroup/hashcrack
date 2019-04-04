import sys

def leetify(i, a, n, t, p):
    # i is first bit, a is remaining bit of word
    # t is number of swaps we've done
    # p is recursion depth

    # only do up to 16 chars, or 4 swaps
    if t>3 or p>16:
        print(i+a)
        return

    #if we've got letters left, process them and fork if
    #it's one of the leet substituions
    if n>0:        
        c=a[0]
        m=n-1        
        d=c.lower()

        leetify(i+c,a[1:],m,t,p+1)

        if d=='o':
            leetify(i+'0',a[1:],m,t+1,p+1)

        if c=='e':
            leetify(i+'3',a[1:],m,t+1,p+1)
        
        if d=='s':
            leetify(i+'5',a[1:],m,t+1,p+1)
            leetify(i+'$',a[1:],m,t+1,p+1)

        if c=='a':
            leetify(i+'@',a[1:],m,t+1,p+1) 
            
        if c=='A':
            leetify(i+'4',a[1:],m,t+1,p+1)
                                               
    else:
        # no letters left, so just dump what we've got
        print(i)
        

with open(sys.argv[1],'r') as inpfile:
    for l in inpfile:
        w=l.rstrip()
        leetify('',w,len(w),0,0)

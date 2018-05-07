import network_awareness as na

G = {1:{2,3},
     2:{1,3},
     3:{1,2,4},
     4:{3}
}

def find_cir_starts_with(G, length, path):
    l, last = len(path), path[-1]
    cnt = 0
    if l==length-1:
        for i in G[last]:
            if (i > path[1]) and (i not in path) and (path[0] in G[i]):
                print(path + [i])
                cnt += 1
    else:
        for i in G[last]:
            if (i > path[0]) and (i not in path):
                cnt += find_cir_starts_with(G, length, path + [i])
    return cnt

def find_cir_of_length(G, n, length):
    cnt = 0
    for i in range(1, n-length+2):
        cnt += find_cir_starts_with(G, length, [i])
    return cnt

def find_all_cirs(G, n):
    cnt = 0
    for i in range(3, n+1):
        cnt += find_cir_of_length(G, n, i)
    return cnt

c = find_all_cirs(G, 4)
print(c)


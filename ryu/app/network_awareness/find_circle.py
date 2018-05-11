import network_awareness as na

G = {1:{2,3},
     2:{1,3},
     3:{1,2,4},
     4:{3}
}

def find_cir_starts_with(G, length, path, cir_list):
    l, last = len(path), path[-1]
    cnt = 0
    if l==length-1:
        for i in G[last]:
            if (i > path[1]) and (i not in path) and (path[0] in G[i]):
                #print(path + [i])
                cir_list.append(path+[i])
                #print(cir_list)
                cnt += 1
    else:
        for i in G[last]:
            if (i > path[0]) and (i not in path):
                cnt += find_cir_starts_with(G, length, path + [i], cir_list)
    return cnt

def find_cir_of_length(G, n, length, cir_list):
    cnt = 0
    for i in range(1, n-length+2):
        cnt += find_cir_starts_with(G, length, [i], cir_list)
    return cnt

def find_all_cirs(G, n, cir_list):
    cnt = 0
    cir_list.clear()
    for i in range(3, n+1):
        cnt += find_cir_of_length(G, n, i, cir_list)
    return cnt

#c = find_all_cirs(G, 4)
#print(c)


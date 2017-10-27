Description of the Program:

The program initially calls the main function, where the flags are taken as the arguments using the 'getopt' method. These flags are then passed as arguments to the appropriate pcap methods. Live capturing is looked after by the pcap_open_live() method and reading of the .pcap file is taken care by pcap_offline() method. The output from this is then compiled using the pcap_compile() method. If any filter is given as an argument then it is handled using pcap_setfilter() method. Then the result is stored as 'handle' and this is made to run in a loop until the user exits or the .pcap file ends and is done using the pcap_loop() method. 'got_packet' method is then called and according to the filter applied, only those functions corresponding to the filters are called. If we dont give any filter as the input then depending upon the packet type the correspoding function is called. If the packet is an ARP packet then print_arp is called or if it is a TCP packet then print_tcp is called or if it is a UDP packet then print_udp is called or if it is an icmp packet then print_icmp is called. If the packet cannot be identified then "Unknown Packet" is printed. Each of these corresponding packets then executes the methods and prints the corresponsing output which can be seen below.

The flags that are used in the program are:

-i => to capture the live interface

-r => to read the .pcap files

-s => to give a substring that is to be searched in the payload.


Command :

sudo ./mydump -r hw1.pcap -s GET

Output :

2013-01-14 02:52:53.882844 00:0C:29:E9:94:8E -> C4:3D:C7:17:6F:9B type 0x800 len 320
192.168.0.200:54634 -> 91.189.91.14:80 TCP
00000   47 45 54 20 2f 75 62 75  6e 74 75 2f 64 69 73 74    GET /ubuntu/dist
00016   73 2f 6f 6e 65 69 72 69  63 2d 75 70 64 61 74 65    s/oneiric-update
00032   73 2f 72 65 73 74 72 69  63 74 65 64 2f 69 31 38    s/restricted/i18
00048   6e 2f 49 6e 64 65 78 20  48 54 54 50 2f 31 2e 31    n/Index HTTP/1.1
00064   0d 0a 48 6f 73 74 3a 20  75 73 2e 61 72 63 68 69    ..Host: us.archi
00080   76 65 2e 75 62 75 6e 74  75 2e 63 6f 6d 0d 0a 43    ve.ubuntu.com..C
00096   6f 6e 6e 65 63 74 69 6f  6e 3a 20 6b 65 65 70 2d    onnection: keep-
00112   61 6c 69 76 65 0d 0a 43  61 63 68 65 2d 43 6f 6e    alive..Cache-Con
00128   74 72 6f 6c 3a 20 6d 61  78 2d 61 67 65 3d 30 0d    trol: max-age=0.
00144   0a 49 66 2d 4d 6f 64 69  66 69 65 64 2d 53 69 6e    .If-Modified-Sin
00160   63 65 3a 20 57 65 64 2c  20 30 39 20 4a 61 6e 20    ce: Wed, 09 Jan 
00176   32 30 31 33 20 32 31 3a  33 33 3a 31 35 20 47 4d    2013 21:33:15 GM
00192   54 0d 0a 55 73 65 72 2d  41 67 65 6e 74 3a 20 44    T..User-Agent: D
00208   65 62 69 61 6e 20 41 50  54 2d 48 54 54 50 2f 31    ebian APT-HTTP/1
00224   2e 33 20 28 30 2e 38 2e  31 36 7e 65 78 70 35 75    .3 (0.8.16~exp5u
00240   62 75 6e 74 75 31 33 2e  36 29 0d 0a 0d 0a          buntu13.6)....
2013-01-14 02:52:54.025756 00:0C:29:E9:94:8E -> C4:3D:C7:17:6F:9B type 0x800 len 318
192.168.0.200:54634 -> 91.189.91.14:80 TCP
00000   47 45 54 20 2f 75 62 75  6e 74 75 2f 64 69 73 74    GET /ubuntu/dist
00016   73 2f 6f 6e 65 69 72 69  63 2d 75 70 64 61 74 65    s/oneiric-update
00032   73 2f 75 6e 69 76 65 72  73 65 2f 69 31 38 6e 2f    s/universe/i18n/
00048   49 6e 64 65 78 20 48 54  54 50 2f 31 2e 31 0d 0a    Index HTTP/1.1..
00064   48 6f 73 74 3a 20 75 73  2e 61 72 63 68 69 76 65    Host: us.archive
00080   2e 75 62 75 6e 74 75 2e  63 6f 6d 0d 0a 43 6f 6e    .ubuntu.com..Con
00096   6e 65 63 74 69 6f 6e 3a  20 6b 65 65 70 2d 61 6c    nection: keep-al
00112   69 76 65 0d 0a 43 61 63  68 65 2d 43 6f 6e 74 72    ive..Cache-Contr
00128   6f 6c 3a 20 6d 61 78 2d  61 67 65 3d 30 0d 0a 49    ol: max-age=0..I
00144   66 2d 4d 6f 64 69 66 69  65 64 2d 53 69 6e 63 65    f-Modified-Since
00160   3a 20 57 65 64 2c 20 30  39 20 4a 61 6e 20 32 30    : Wed, 09 Jan 20
00176   31 33 20 32 31 3a 33 33  3a 31 35 20 47 4d 54 0d    13 21:33:15 GMT.
00192   0a 55 73 65 72 2d 41 67  65 6e 74 3a 20 44 65 62    .User-Agent: Deb
00208   69 61 6e 20 41 50 54 2d  48 54 54 50 2f 31 2e 33    ian APT-HTTP/1.3
00224   20 28 30 2e 38 2e 31 36  7e 65 78 70 35 75 62 75     (0.8.16~exp5ubu
00240   6e 74 75 31 33 2e 36 29  0d 0a 0d 0a                ntu13.6)....
2013-01-14 02:52:54.133711 00:0C:29:E9:94:8E -> C4:3D:C7:17:6F:9B type 0x800 len 588
192.168.0.200:54634 -> 91.189.91.14:80 TCP
00000   47 45 54 20 2f 75 62 75  6e 74 75 2f 64 69 73 74    GET /ubuntu/dist
00016   73 2f 6f 6e 65 69 72 69  63 2d 62 61 63 6b 70 6f    s/oneiric-backpo
00032   72 74 73 2f 6d 61 69 6e  2f 73 6f 75 72 63 65 2f    rts/main/source/
00048   53 6f 75 72 63 65 73 2e  62 7a 32 20 48 54 54 50    Sources.bz2 HTTP
00064   2f 31 2e 31 0d 0a 48 6f  73 74 3a 20 75 73 2e 61    /1.1..Host: us.a
00080   72 63 68 69 76 65 2e 75  62 75 6e 74 75 2e 63 6f    rchive.ubuntu.co
00096   6d 0d 0a 43 6f 6e 6e 65  63 74 69 6f 6e 3a 20 6b    m..Connection: k
00112   65 65 70 2d 61 6c 69 76  65 0d 0a 43 61 63 68 65    eep-alive..Cache
00128   2d 43 6f 6e 74 72 6f 6c  3a 20 6d 61 78 2d 61 67    -Control: max-ag
00144   65 3d 30 0d 0a 49 66 2d  4d 6f 64 69 66 69 65 64    e=0..If-Modified
00160   2d 53 69 6e 63 65 3a 20  4d 6f 6e 2c 20 31 35 20    -Since: Mon, 15 
00176   4f 63 74 20 32 30 31 32  20 30 32 3a 33 35 3a 31    Oct 2012 02:35:1
00192   39 20 47 4d 54 0d 0a 55  73 65 72 2d 41 67 65 6e    9 GMT..User-Agen
00208   74 3a 20 44 65 62 69 61  6e 20 41 50 54 2d 48 54    t: Debian APT-HT
00224   54 50 2f 31 2e 33 20 28  30 2e 38 2e 31 36 7e 65    TP/1.3 (0.8.16~e
00240   78 70 35 75 62 75 6e 74  75 31 33 2e 36 29 0d 0a    xp5ubuntu13.6)..
00256   0d 0a 47 45 54 20 2f 75  62 75 6e 74 75 2f 64 69    ..GET /ubuntu/di
00272   73 74 73 2f 6f 6e 65 69  72 69 63 2d 62 61 63 6b    sts/oneiric-back
00288   70 6f 72 74 73 2f 72 65  73 74 72 69 63 74 65 64    ports/restricted
00304   2f 73 6f 75 72 63 65 2f  53 6f 75 72 63 65 73 2e    /source/Sources.
00320   62 7a 32 20 48 54 54 50  2f 31 2e 31 0d 0a 48 6f    bz2 HTTP/1.1..Ho
00336   73 74 3a 20 75 73 2e 61  72 63 68 69 76 65 2e 75    st: us.archive.u
00352   62 75 6e 74 75 2e 63 6f  6d 0d 0a 43 6f 6e 6e 65    buntu.com..Conne
00368   63 74 69 6f 6e 3a 20 6b  65 65 70 2d 61 6c 69 76    ction: keep-aliv
00384   65 0d 0a 43 61 63 68 65  2d 43 6f 6e 74 72 6f 6c    e..Cache-Control
00400   3a 20 6d 61 78 2d 61 67  65 3d 30 0d 0a 49 66 2d    : max-age=0..If-
00416   4d 6f 64 69 66 69 65 64  2d 53 69 6e 63 65 3a 20    Modified-Since: 
00432   4d 6f 6e 2c 20 31 35 20  4f 63 74 20 32 30 31 32    Mon, 15 Oct 2012
00448   20 30 32 3a 33 35 3a 31  39 20 47 4d 54 0d 0a 55     02:35:19 GMT..U
00464   73 65 72 2d 41 67 65 6e  74 3a 20 44 65 62 69 61    ser-Agent: Debia
00480   6e 20 41 50 54 2d 48 54  54 50 2f 31 2e 33 20 28    n APT-HTTP/1.3 (
00496   30 2e 38 2e 31 36 7e 65  78 70 35 75 62 75 6e 74    0.8.16~exp5ubunt
00512   75 31 33 2e 36 29 0d 0a  0d 0a                      u13.6)....
2013-01-14 02:52:54.464350 00:0C:29:E9:94:8E -> C4:3D:C7:17:6F:9B type 0x800 len 592
192.168.0.200:54634 -> 91.189.91.14:80 TCP
00000   47 45 54 20 2f 75 62 75  6e 74 75 2f 64 69 73 74    GET /ubuntu/dist
00016   73 2f 6f 6e 65 69 72 69  63 2d 62 61 63 6b 70 6f    s/oneiric-backpo
00032   72 74 73 2f 75 6e 69 76  65 72 73 65 2f 73 6f 75    rts/universe/sou
00048   72 63 65 2f 53 6f 75 72  63 65 73 2e 62 7a 32 20    rce/Sources.bz2 
00064   48 54 54 50 2f 31 2e 31  0d 0a 48 6f 73 74 3a 20    HTTP/1.1..Host: 
00080   75 73 2e 61 72 63 68 69  76 65 2e 75 62 75 6e 74    us.archive.ubunt
00096   75 2e 63 6f 6d 0d 0a 43  6f 6e 6e 65 63 74 69 6f    u.com..Connectio
00112   6e 3a 20 6b 65 65 70 2d  61 6c 69 76 65 0d 0a 43    n: keep-alive..C
00128   61 63 68 65 2d 43 6f 6e  74 72 6f 6c 3a 20 6d 61    ache-Control: ma
00144   78 2d 61 67 65 3d 30 0d  0a 49 66 2d 4d 6f 64 69    x-age=0..If-Modi
00160   66 69 65 64 2d 53 69 6e  63 65 3a 20 4d 6f 6e 2c    fied-Since: Mon,
00176   20 31 35 20 4f 63 74 20  32 30 31 32 20 30 32 3a     15 Oct 2012 02:
00192   33 35 3a 31 39 20 47 4d  54 0d 0a 55 73 65 72 2d    35:19 GMT..User-
00208   41 67 65 6e 74 3a 20 44  65 62 69 61 6e 20 41 50    Agent: Debian AP
00224   54 2d 48 54 54 50 2f 31  2e 33 20 28 30 2e 38 2e    T-HTTP/1.3 (0.8.
00240   31 36 7e 65 78 70 35 75  62 75 6e 74 75 31 33 2e    16~exp5ubuntu13.
00256   36 29 0d 0a 0d 0a 47 45  54 20 2f 75 62 75 6e 74    6)....GET /ubunt
00272   75 2f 64 69 73 74 73 2f  6f 6e 65 69 72 69 63 2d    u/dists/oneiric-
00288   62 61 63 6b 70 6f 72 74  73 2f 6d 75 6c 74 69 76    backports/multiv
00304   65 72 73 65 2f 73 6f 75  72 63 65 2f 53 6f 75 72    erse/source/Sour
00320   63 65 73 2e 62 7a 32 20  48 54 54 50 2f 31 2e 31    ces.bz2 HTTP/1.1
00336   0d 0a 48 6f 73 74 3a 20  75 73 2e 61 72 63 68 69    ..Host: us.archi
00352   76 65 2e 75 62 75 6e 74  75 2e 63 6f 6d 0d 0a 43    ve.ubuntu.com..C
00368   6f 6e 6e 65 63 74 69 6f  6e 3a 20 6b 65 65 70 2d    onnection: keep-
00384   61 6c 69 76 65 0d 0a 43  61 63 68 65 2d 43 6f 6e    alive..Cache-Con
00400   74 72 6f 6c 3a 20 6d 61  78 2d 61 67 65 3d 30 0d    trol: max-age=0.
00416   0a 49 66 2d 4d 6f 64 69  66 69 65 64 2d 53 69 6e    .If-Modified-Sin
00432   63 65 3a 20 4d 6f 6e 2c  20 31 35 20 4f 63 74 20    ce: Mon, 15 Oct 
00448   32 30 31 32 20 30 32 3a  33 35 3a 31 39 20 47 4d    2012 02:35:19 GM
00464   54 0d 0a 55 73 65 72 2d  41 67 65 6e 74 3a 20 44    T..User-Agent: D
00480   65 62 69 61 6e 20 41 50  54 2d 48 54 54 50 2f 31    ebian APT-HTTP/1
00496   2e 33 20 28 30 2e 38 2e  31 36 7e 65 78 70 35 75    .3 (0.8.16~exp5u
00512   62 75 6e 74 75 31 33 2e  36 29 0d 0a 0d 0a          buntu13.6)....
2013-01-14 02:52:54.706714 00:0C:29:E9:94:8E -> C4:3D:C7:17:6F:9B type 0x800 len 1514
192.168.0.200:54634 -> 91.189.91.14:80 TCP
00000   47 45 54 20 2f 75 62 75  6e 74 75 2f 64 69 73 74    GET /ubuntu/dist
00016   73 2f 6f 6e 65 69 72 69  63 2d 62 61 63 6b 70 6f    s/oneiric-backpo
00032   72 74 73 2f 6d 61 69 6e  2f 62 69 6e 61 72 79 2d    rts/main/binary-
00048   69 33 38 36 2f 50 61 63  6b 61 67 65 73 2e 62 7a    i386/Packages.bz
00064   32 20 48 54 54 50 2f 31  2e 31 0d 0a 48 6f 73 74    2 HTTP/1.1..Host
00080   3a 20 75 73 2e 61 72 63  68 69 76 65 2e 75 62 75    : us.archive.ubu
00096   6e 74 75 2e 63 6f 6d 0d  0a 43 6f 6e 6e 65 63 74    ntu.com..Connect
00112   69 6f 6e 3a 20 6b 65 65  70 2d 61 6c 69 76 65 0d    ion: keep-alive.
00128   0a 43 61 63 68 65 2d 43  6f 6e 74 72 6f 6c 3a 20    .Cache-Control: 
00144   6d 61 78 2d 61 67 65 3d  30 0d 0a 49 66 2d 4d 6f    max-age=0..If-Mo
00160   64 69 66 69 65 64 2d 53  69 6e 63 65 3a 20 4d 6f    dified-Since: Mo
00176   6e 2c 20 31 35 20 4f 63  74 20 32 30 31 32 20 30    n, 15 Oct 2012 0
00192   32 3a 33 34 3a 35 38 20  47 4d 54 0d 0a 55 73 65    2:34:58 GMT..Use
00208   72 2d 41 67 65 6e 74 3a  20 44 65 62 69 61 6e 20    r-Agent: Debian 
00224   41 50 54 2d 48 54 54 50  2f 31 2e 33 20 28 30 2e    APT-HTTP/1.3 (0.
00240   38 2e 31 36 7e 65 78 70  35 75 62 75 6e 74 75 31    8.16~exp5ubuntu1
00256   33 2e 36 29 0d 0a 0d 0a  47 45 54 20 2f 75 62 75    3.6)....GET /ubu
00272   6e 74 75 2f 64 69 73 74  73 2f 6f 6e 65 69 72 69    ntu/dists/oneiri
00288   63 2d 62 61 63 6b 70 6f  72 74 73 2f 72 65 73 74    c-backports/rest
00304   72 69 63 74 65 64 2f 62  69 6e 61 72 79 2d 69 33    ricted/binary-i3
00320   38 36 2f 50 61 63 6b 61  67 65 73 2e 62 7a 32 20    86/Packages.bz2 
00336   48 54 54 50 2f 31 2e 31  0d 0a 48 6f 73 74 3a 20    HTTP/1.1..Host: 
00352   75 73 2e 61 72 63 68 69  76 65 2e 75 62 75 6e 74    us.archive.ubunt
00368   75 2e 63 6f 6d 0d 0a 43  6f 6e 6e 65 63 74 69 6f    u.com..Connectio
00384   6e 3a 20 6b 65 65 70 2d  61 6c 69 76 65 0d 0a 43    n: keep-alive..C
00400   61 63 68 65 2d 43 6f 6e  74 72 6f 6c 3a 20 6d 61    ache-Control: ma
00416   78 2d 61 67 65 3d 30 0d  0a 49 66 2d 4d 6f 64 69    x-age=0..If-Modi
00432   66 69 65 64 2d 53 69 6e  63 65 3a 20 4d 6f 6e 2c    fied-Since: Mon,
00448   20 31 35 20 4f 63 74 20  32 30 31 32 20 30 32 3a     15 Oct 2012 02:
00464   33 34 3a 35 38 20 47 4d  54 0d 0a 55 73 65 72 2d    34:58 GMT..User-
00480   41 67 65 6e 74 3a 20 44  65 62 69 61 6e 20 41 50    Agent: Debian AP
00496   54 2d 48 54 54 50 2f 31  2e 33 20 28 30 2e 38 2e    T-HTTP/1.3 (0.8.
00512   31 36 7e 65 78 70 35 75  62 75 6e 74 75 31 33 2e    16~exp5ubuntu13.
00528   36 29 0d 0a 0d 0a 47 45  54 20 2f 75 62 75 6e 74    6)....GET /ubunt
00544   75 2f 64 69 73 74 73 2f  6f 6e 65 69 72 69 63 2d    u/dists/oneiric-
00560   62 61 63 6b 70 6f 72 74  73 2f 75 6e 69 76 65 72    backports/univer
00576   73 65 2f 62 69 6e 61 72  79 2d 69 33 38 36 2f 50    se/binary-i386/P
00592   61 63 6b 61 67 65 73 2e  62 7a 32 20 48 54 54 50    ackages.bz2 HTTP
00608   2f 31 2e 31 0d 0a 48 6f  73 74 3a 20 75 73 2e 61    /1.1..Host: us.a
00624   72 63 68 69 76 65 2e 75  62 75 6e 74 75 2e 63 6f    rchive.ubuntu.co
00640   6d 0d 0a 43 6f 6e 6e 65  63 74 69 6f 6e 3a 20 6b    m..Connection: k
00656   65 65 70 2d 61 6c 69 76  65 0d 0a 43 61 63 68 65    eep-alive..Cache
00672   2d 43 6f 6e 74 72 6f 6c  3a 20 6d 61 78 2d 61 67    -Control: max-ag
00688   65 3d 30 0d 0a 49 66 2d  4d 6f 64 69 66 69 65 64    e=0..If-Modified
00704   2d 53 69 6e 63 65 3a 20  4d 6f 6e 2c 20 31 35 20    -Since: Mon, 15 
00720   4f 63 74 20 32 30 31 32  20 30 32 3a 33 34 3a 35    Oct 2012 02:34:5
00736   39 20 47 4d 54 0d 0a 55  73 65 72 2d 41 67 65 6e    9 GMT..User-Agen
00752   74 3a 20 44 65 62 69 61  6e 20 41 50 54 2d 48 54    t: Debian APT-HT
00768   54 50 2f 31 2e 33 20 28  30 2e 38 2e 31 36 7e 65    TP/1.3 (0.8.16~e
00784   78 70 35 75 62 75 6e 74  75 31 33 2e 36 29 0d 0a    xp5ubuntu13.6)..
00800   0d 0a 47 45 54 20 2f 75  62 75 6e 74 75 2f 64 69    ..GET /ubuntu/di
00816   73 74 73 2f 6f 6e 65 69  72 69 63 2d 62 61 63 6b    sts/oneiric-back
00832   70 6f 72 74 73 2f 6d 75  6c 74 69 76 65 72 73 65    ports/multiverse
00848   2f 62 69 6e 61 72 79 2d  69 33 38 36 2f 50 61 63    /binary-i386/Pac
00864   6b 61 67 65 73 2e 62 7a  32 20 48 54 54 50 2f 31    kages.bz2 HTTP/1
00880   2e 31 0d 0a 48 6f 73 74  3a 20 75 73 2e 61 72 63    .1..Host: us.arc
00896   68 69 76 65 2e 75 62 75  6e 74 75 2e 63 6f 6d 0d    hive.ubuntu.com.
00912   0a 43 6f 6e 6e 65 63 74  69 6f 6e 3a 20 6b 65 65    .Connection: kee
00928   70 2d 61 6c 69 76 65 0d  0a 43 61 63 68 65 2d 43    p-alive..Cache-C
00944   6f 6e 74 72 6f 6c 3a 20  6d 61 78 2d 61 67 65 3d    ontrol: max-age=
00960   30 0d 0a 49 66 2d 4d 6f  64 69 66 69 65 64 2d 53    0..If-Modified-S
00976   69 6e 63 65 3a 20 4d 6f  6e 2c 20 31 35 20 4f 63    ince: Mon, 15 Oc
00992   74 20 32 30 31 32 20 30  32 3a 33 34 3a 35 39 20    t 2012 02:34:59 
01008   47 4d 54 0d 0a 55 73 65  72 2d 41 67 65 6e 74 3a    GMT..User-Agent:
01024   20 44 65 62 69 61 6e 20  41 50 54 2d 48 54 54 50     Debian APT-HTTP
01040   2f 31 2e 33 20 28 30 2e  38 2e 31 36 7e 65 78 70    /1.3 (0.8.16~exp
01056   35 75 62 75 6e 74 75 31  33 2e 36 29 0d 0a 0d 0a    5ubuntu13.6)....
01072   47 45 54 20 2f 75 62 75  6e 74 75 2f 64 69 73 74    GET /ubuntu/dist
01088   73 2f 6f 6e 65 69 72 69  63 2d 62 61 63 6b 70 6f    s/oneiric-backpo
01104   72 74 73 2f 6d 61 69 6e  2f 69 31 38 6e 2f 49 6e    rts/main/i18n/In
01120   64 65 78 20 48 54 54 50  2f 31 2e 31 0d 0a 48 6f    dex HTTP/1.1..Ho
01136   73 74 3a 20 75 73 2e 61  72 63 68 69 76 65 2e 75    st: us.archive.u
01152   62 75 6e 74 75 2e 63 6f  6d 0d 0a 43 6f 6e 6e 65    buntu.com..Conne
01168   63 74 69 6f 6e 3a 20 6b  65 65 70 2d 61 6c 69 76    ction: keep-aliv
01184   65 0d 0a 43 61 63 68 65  2d 43 6f 6e 74 72 6f 6c    e..Cache-Control
01200   3a 20 6d 61 78 2d 61 67  65 3d 30 0d 0a 49 66 2d    : max-age=0..If-
01216   4d 6f 64 69 66 69 65 64  2d 53 69 6e 63 65 3a 20    Modified-Since: 
01232   4d 6f 6e 2c 20 31 35 20  4f 63 74 20 32 30 31 32    Mon, 15 Oct 2012
01248   20 30 32 3a 33 35 3a 32  31 20 47 4d 54 0d 0a 55     02:35:21 GMT..U
01264   73 65 72 2d 41 67 65 6e  74 3a 20 44 65 62 69 61    ser-Agent: Debia
01280   6e 20 41 50 54 2d 48 54  54 50 2f 31 2e 33 20 28    n APT-HTTP/1.3 (
01296   30 2e 38 2e 31 36 7e 65  78 70 35 75 62 75 6e 74    0.8.16~exp5ubunt
01312   75 31 33 2e 36 29 0d 0a  0d 0a 47 45 54 20 2f 75    u13.6)....GET /u
01328   62 75 6e 74 75 2f 64 69  73 74 73 2f 6f 6e 65 69    buntu/dists/onei
01344   72 69 63 2d 62 61 63 6b  70 6f 72 74 73 2f 6d 75    ric-backports/mu
01360   6c 74 69 76 65 72 73 65  2f 69 31 38 6e 2f 49 6e    ltiverse/i18n/In
01376   64 65 78 20 48 54 54 50  2f 31 2e 31 0d 0a 48 6f    dex HTTP/1.1..Ho
01392   73 74 3a 20 75 73 2e 61  72 63 68 69 76 65 2e 75    st: us.archive.u
01408   62 75 6e 74 75 2e 63 6f  6d 0d 0a 43 6f 6e 6e 65    buntu.com..Conne
01424   63 74 69 6f 6e 3a 20 6b  65 65 70 2d 61 6c 69 76    ction: keep-aliv
01440   65 0d 0a 43 61 63 68 65                             e..Cache
2013-01-14 02:52:54.706937 00:0C:29:E9:94:8E -> C4:3D:C7:17:6F:9B type 0x800 len 1218
192.168.0.200:54634 -> 91.189.91.14:80 TCP
00000   2d 43 6f 6e 74 72 6f 6c  3a 20 6d 61 78 2d 61 67    -Control: max-ag
00016   65 3d 30 0d 0a 49 66 2d  4d 6f 64 69 66 69 65 64    e=0..If-Modified
00032   2d 53 69 6e 63 65 3a 20  4d 6f 6e 2c 20 31 35 20    -Since: Mon, 15 
00048   4f 63 74 20 32 30 31 32  20 30 32 3a 33 35 3a 32    Oct 2012 02:35:2
00064   31 20 47 4d 54 0d 0a 55  73 65 72 2d 41 67 65 6e    1 GMT..User-Agen
00080   74 3a 20 44 65 62 69 61  6e 20 41 50 54 2d 48 54    t: Debian APT-HT
00096   54 50 2f 31 2e 33 20 28  30 2e 38 2e 31 36 7e 65    TP/1.3 (0.8.16~e
00112   78 70 35 75 62 75 6e 74  75 31 33 2e 36 29 0d 0a    xp5ubuntu13.6)..
00128   0d 0a 47 45 54 20 2f 75  62 75 6e 74 75 2f 64 69    ..GET /ubuntu/di
00144   73 74 73 2f 6f 6e 65 69  72 69 63 2d 62 61 63 6b    sts/oneiric-back
00160   70 6f 72 74 73 2f 72 65  73 74 72 69 63 74 65 64    ports/restricted
00176   2f 69 31 38 6e 2f 49 6e  64 65 78 20 48 54 54 50    /i18n/Index HTTP
00192   2f 31 2e 31 0d 0a 48 6f  73 74 3a 20 75 73 2e 61    /1.1..Host: us.a
00208   72 63 68 69 76 65 2e 75  62 75 6e 74 75 2e 63 6f    rchive.ubuntu.co
00224   6d 0d 0a 43 6f 6e 6e 65  63 74 69 6f 6e 3a 20 6b    m..Connection: k
00240   65 65 70 2d 61 6c 69 76  65 0d 0a 43 61 63 68 65    eep-alive..Cache
00256   2d 43 6f 6e 74 72 6f 6c  3a 20 6d 61 78 2d 61 67    -Control: max-ag
00272   65 3d 30 0d 0a 49 66 2d  4d 6f 64 69 66 69 65 64    e=0..If-Modified
00288   2d 53 69 6e 63 65 3a 20  4d 6f 6e 2c 20 31 35 20    -Since: Mon, 15 
00304   4f 63 74 20 32 30 31 32  20 30 32 3a 33 35 3a 32    Oct 2012 02:35:2
00320   31 20 47 4d 54 0d 0a 55  73 65 72 2d 41 67 65 6e    1 GMT..User-Agen
00336   74 3a 20 44 65 62 69 61  6e 20 41 50 54 2d 48 54    t: Debian APT-HT
00352   54 50 2f 31 2e 33 20 28  30 2e 38 2e 31 36 7e 65    TP/1.3 (0.8.16~e
00368   78 70 35 75 62 75 6e 74  75 31 33 2e 36 29 0d 0a    xp5ubuntu13.6)..
00384   0d 0a 47 45 54 20 2f 75  62 75 6e 74 75 2f 64 69    ..GET /ubuntu/di
00400   73 74 73 2f 6f 6e 65 69  72 69 63 2d 62 61 63 6b    sts/oneiric-back
00416   70 6f 72 74 73 2f 75 6e  69 76 65 72 73 65 2f 69    ports/universe/i
00432   31 38 6e 2f 49 6e 64 65  78 20 48 54 54 50 2f 31    18n/Index HTTP/1
00448   2e 31 0d 0a 48 6f 73 74  3a 20 75 73 2e 61 72 63    .1..Host: us.arc
00464   68 69 76 65 2e 75 62 75  6e 74 75 2e 63 6f 6d 0d    hive.ubuntu.com.
00480   0a 43 6f 6e 6e 65 63 74  69 6f 6e 3a 20 6b 65 65    .Connection: kee
00496   70 2d 61 6c 69 76 65 0d  0a 43 61 63 68 65 2d 43    p-alive..Cache-C
00512   6f 6e 74 72 6f 6c 3a 20  6d 61 78 2d 61 67 65 3d    ontrol: max-age=
00528   30 0d 0a 49 66 2d 4d 6f  64 69 66 69 65 64 2d 53    0..If-Modified-S
00544   69 6e 63 65 3a 20 4d 6f  6e 2c 20 31 35 20 4f 63    ince: Mon, 15 Oc
00560   74 20 32 30 31 32 20 30  32 3a 33 35 3a 32 31 20    t 2012 02:35:21 
00576   47 4d 54 0d 0a 55 73 65  72 2d 41 67 65 6e 74 3a    GMT..User-Agent:
00592   20 44 65 62 69 61 6e 20  41 50 54 2d 48 54 54 50     Debian APT-HTTP
00608   2f 31 2e 33 20 28 30 2e  38 2e 31 36 7e 65 78 70    /1.3 (0.8.16~exp
00624   35 75 62 75 6e 74 75 31  33 2e 36 29 0d 0a 0d 0a    5ubuntu13.6)....
00640   47 45 54 20 2f 75 62 75  6e 74 75 2f 64 69 73 74    GET /ubuntu/dist
00656   73 2f 6f 6e 65 69 72 69  63 2f 6d 61 69 6e 2f 69    s/oneiric/main/i
00672   31 38 6e 2f 54 72 61 6e  73 6c 61 74 69 6f 6e 2d    18n/Translation-
00688   65 6e 2e 62 7a 32 20 48  54 54 50 2f 31 2e 31 0d    en.bz2 HTTP/1.1.
00704   0a 48 6f 73 74 3a 20 75  73 2e 61 72 63 68 69 76    .Host: us.archiv
00720   65 2e 75 62 75 6e 74 75  2e 63 6f 6d 0d 0a 43 6f    e.ubuntu.com..Co
00736   6e 6e 65 63 74 69 6f 6e  3a 20 6b 65 65 70 2d 61    nnection: keep-a
00752   6c 69 76 65 0d 0a 43 61  63 68 65 2d 43 6f 6e 74    live..Cache-Cont
00768   72 6f 6c 3a 20 6d 61 78  2d 61 67 65 3d 30 0d 0a    rol: max-age=0..
00784   49 66 2d 4d 6f 64 69 66  69 65 64 2d 53 69 6e 63    If-Modified-Sinc
00800   65 3a 20 57 65 64 2c 20  31 32 20 4f 63 74 20 32    e: Wed, 12 Oct 2
00816   30 31 31 20 30 35 3a 33  32 3a 35 30 20 47 4d 54    011 05:32:50 GMT
00832   0d 0a 55 73 65 72 2d 41  67 65 6e 74 3a 20 44 65    ..User-Agent: De
00848   62 69 61 6e 20 41 50 54  2d 48 54 54 50 2f 31 2e    bian APT-HTTP/1.
00864   33 20 28 30 2e 38 2e 31  36 7e 65 78 70 35 75 62    3 (0.8.16~exp5ub
00880   75 6e 74 75 31 33 2e 36  29 0d 0a 0d 0a 47 45 54    untu13.6)....GET
00896   20 2f 75 62 75 6e 74 75  2f 64 69 73 74 73 2f 6f     /ubuntu/dists/o
00912   6e 65 69 72 69 63 2f 6d  75 6c 74 69 76 65 72 73    neiric/multivers
00928   65 2f 69 31 38 6e 2f 54  72 61 6e 73 6c 61 74 69    e/i18n/Translati
00944   6f 6e 2d 65 6e 2e 62 7a  32 20 48 54 54 50 2f 31    on-en.bz2 HTTP/1
00960   2e 31 0d 0a 48 6f 73 74  3a 20 75 73 2e 61 72 63    .1..Host: us.arc
00976   68 69 76 65 2e 75 62 75  6e 74 75 2e 63 6f 6d 0d    hive.ubuntu.com.
00992   0a 43 6f 6e 6e 65 63 74  69 6f 6e 3a 20 6b 65 65    .Connection: kee
01008   70 2d 61 6c 69 76 65 0d  0a 43 61 63 68 65 2d 43    p-alive..Cache-C
01024   6f 6e 74 72 6f 6c 3a 20  6d 61 78 2d 61 67 65 3d    ontrol: max-age=
01040   30 0d 0a 49 66 2d 4d 6f  64 69 66 69 65 64 2d 53    0..If-Modified-S
01056   69 6e 63 65 3a 20 54 75  65 2c 20 30 34 20 4f 63    ince: Tue, 04 Oc
01072   74 20 32 30 31 31 20 30  39 3a 31 36 3a 34 33 20    t 2011 09:16:43 
01088   47 4d 54 0d 0a 55 73 65  72 2d 41 67 65 6e 74 3a    GMT..User-Agent:
01104   20 44 65 62 69 61 6e 20  41 50 54 2d 48 54 54 50     Debian APT-HTTP
01120   2f 31 2e 33 20 28 30 2e  38 2e 31 36 7e 65 78 70    /1.3 (0.8.16~exp
01136   35 75 62 75 6e 74 75 31  33 2e 36 29 0d 0a 0d 0a    5ubuntu13.6)....
2013-01-14 02:52:54.951569 00:0C:29:E9:94:8E -> C4:3D:C7:17:6F:9B type 0x800 len 568
192.168.0.200:54634 -> 91.189.91.14:80 TCP
00000   47 45 54 20 2f 75 62 75  6e 74 75 2f 64 69 73 74    GET /ubuntu/dist
00016   73 2f 6f 6e 65 69 72 69  63 2f 72 65 73 74 72 69    s/oneiric/restri
00032   63 74 65 64 2f 69 31 38  6e 2f 54 72 61 6e 73 6c    cted/i18n/Transl
00048   61 74 69 6f 6e 2d 65 6e  2e 62 7a 32 20 48 54 54    ation-en.bz2 HTT
00064   50 2f 31 2e 31 0d 0a 48  6f 73 74 3a 20 75 73 2e    P/1.1..Host: us.
00080   61 72 63 68 69 76 65 2e  75 62 75 6e 74 75 2e 63    archive.ubuntu.c
00096   6f 6d 0d 0a 43 6f 6e 6e  65 63 74 69 6f 6e 3a 20    om..Connection: 
00112   6b 65 65 70 2d 61 6c 69  76 65 0d 0a 43 61 63 68    keep-alive..Cach
00128   65 2d 43 6f 6e 74 72 6f  6c 3a 20 6d 61 78 2d 61    e-Control: max-a
00144   67 65 3d 30 0d 0a 49 66  2d 4d 6f 64 69 66 69 65    ge=0..If-Modifie
00160   64 2d 53 69 6e 63 65 3a  20 54 75 65 2c 20 32 37    d-Since: Tue, 27
00176   20 53 65 70 20 32 30 31  31 20 30 39 3a 31 37 3a     Sep 2011 09:17:
00192   33 38 20 47 4d 54 0d 0a  55 73 65 72 2d 41 67 65    38 GMT..User-Age
00208   6e 74 3a 20 44 65 62 69  61 6e 20 41 50 54 2d 48    nt: Debian APT-H
00224   54 54 50 2f 31 2e 33 20  28 30 2e 38 2e 31 36 7e    TTP/1.3 (0.8.16~
00240   65 78 70 35 75 62 75 6e  74 75 31 33 2e 36 29 0d    exp5ubuntu13.6).
00256   0a 0d 0a 47 45 54 20 2f  75 62 75 6e 74 75 2f 64    ...GET /ubuntu/d
00272   69 73 74 73 2f 6f 6e 65  69 72 69 63 2f 75 6e 69    ists/oneiric/uni
00288   76 65 72 73 65 2f 69 31  38 6e 2f 54 72 61 6e 73    verse/i18n/Trans
00304   6c 61 74 69 6f 6e 2d 65  6e 2e 62 7a 32 20 48 54    lation-en.bz2 HT
00320   54 50 2f 31 2e 31 0d 0a  48 6f 73 74 3a 20 75 73    TP/1.1..Host: us
00336   2e 61 72 63 68 69 76 65  2e 75 62 75 6e 74 75 2e    .archive.ubuntu.
00352   63 6f 6d 0d 0a 43 6f 6e  6e 65 63 74 69 6f 6e 3a    com..Connection:
00368   20 6b 65 65 70 2d 61 6c  69 76 65 0d 0a 43 61 63     keep-alive..Cac
00384   68 65 2d 43 6f 6e 74 72  6f 6c 3a 20 6d 61 78 2d    he-Control: max-
00400   61 67 65 3d 30 0d 0a 49  66 2d 4d 6f 64 69 66 69    age=0..If-Modifi
00416   65 64 2d 53 69 6e 63 65  3a 20 57 65 64 2c 20 31    ed-Since: Wed, 1
00432   32 20 4f 63 74 20 32 30  31 31 20 31 31 3a 31 36    2 Oct 2011 11:16
00448   3a 32 39 20 47 4d 54 0d  0a 55 73 65 72 2d 41 67    :29 GMT..User-Ag
00464   65 6e 74 3a 20 44 65 62  69 61 6e 20 41 50 54 2d    ent: Debian APT-
00480   48 54 54 50 2f 31 2e 33  20 28 30 2e 38 2e 31 36    HTTP/1.3 (0.8.16
00496   7e 65 78 70 35 75                                   ~exp5u
2013-01-14 02:52:54.953995 00:0C:29:E9:94:8E -> C4:3D:C7:17:6F:9B type 0x800 len 1514
192.168.0.200:54634 -> 91.189.91.14:80 TCP
00000   62 75 6e 74 75 31 33 2e  36 29 0d 0a 0d 0a 47 45    buntu13.6)....GE
00016   54 20 2f 75 62 75 6e 74  75 2f 64 69 73 74 73 2f    T /ubuntu/dists/
00032   6f 6e 65 69 72 69 63 2d  75 70 64 61 74 65 73 2f    oneiric-updates/
00048   6d 61 69 6e 2f 69 31 38  6e 2f 54 72 61 6e 73 6c    main/i18n/Transl
00064   61 74 69 6f 6e 2d 65 6e  2e 62 7a 32 20 48 54 54    ation-en.bz2 HTT
00080   50 2f 31 2e 31 0d 0a 48  6f 73 74 3a 20 75 73 2e    P/1.1..Host: us.
00096   61 72 63 68 69 76 65 2e  75 62 75 6e 74 75 2e 63    archive.ubuntu.c
00112   6f 6d 0d 0a 43 6f 6e 6e  65 63 74 69 6f 6e 3a 20    om..Connection: 
00128   6b 65 65 70 2d 61 6c 69  76 65 0d 0a 43 61 63 68    keep-alive..Cach
00144   65 2d 43 6f 6e 74 72 6f  6c 3a 20 6d 61 78 2d 61    e-Control: max-a
00160   67 65 3d 30 0d 0a 49 66  2d 4d 6f 64 69 66 69 65    ge=0..If-Modifie
00176   64 2d 53 69 6e 63 65 3a  20 57 65 64 2c 20 31 39    d-Since: Wed, 19
00192   20 44 65 63 20 32 30 31  32 20 31 37 3a 33 32 3a     Dec 2012 17:32:
00208   35 38 20 47 4d 54 0d 0a  55 73 65 72 2d 41 67 65    58 GMT..User-Age
00224   6e 74 3a 20 44 65 62 69  61 6e 20 41 50 54 2d 48    nt: Debian APT-H
00240   54 54 50 2f 31 2e 33 20  28 30 2e 38 2e 31 36 7e    TTP/1.3 (0.8.16~
00256   65 78 70 35 75 62 75 6e  74 75 31 33 2e 36 29 0d    exp5ubuntu13.6).
00272   0a 0d 0a 47 45 54 20 2f  75 62 75 6e 74 75 2f 64    ...GET /ubuntu/d
00288   69 73 74 73 2f 6f 6e 65  69 72 69 63 2d 75 70 64    ists/oneiric-upd
00304   61 74 65 73 2f 6d 75 6c  74 69 76 65 72 73 65 2f    ates/multiverse/
00320   69 31 38 6e 2f 54 72 61  6e 73 6c 61 74 69 6f 6e    i18n/Translation
00336   2d 65 6e 2e 62 7a 32 20  48 54 54 50 2f 31 2e 31    -en.bz2 HTTP/1.1
00352   0d 0a 48 6f 73 74 3a 20  75 73 2e 61 72 63 68 69    ..Host: us.archi
00368   76 65 2e 75 62 75 6e 74  75 2e 63 6f 6d 0d 0a 43    ve.ubuntu.com..C
00384   6f 6e 6e 65 63 74 69 6f  6e 3a 20 6b 65 65 70 2d    onnection: keep-
00400   61 6c 69 76 65 0d 0a 43  61 63 68 65 2d 43 6f 6e    alive..Cache-Con
00416   74 72 6f 6c 3a 20 6d 61  78 2d 61 67 65 3d 30 0d    trol: max-age=0.
00432   0a 49 66 2d 4d 6f 64 69  66 69 65 64 2d 53 69 6e    .If-Modified-Sin
00448   63 65 3a 20 54 68 75 2c  20 31 36 20 46 65 62 20    ce: Thu, 16 Feb 
00464   32 30 31 32 20 30 32 3a  35 39 3a 34 32 20 47 4d    2012 02:59:42 GM
00480   54 0d 0a 55 73 65 72 2d  41 67 65 6e 74 3a 20 44    T..User-Agent: D
00496   65 62 69 61 6e 20 41 50  54 2d 48 54 54 50 2f 31    ebian APT-HTTP/1
00512   2e 33 20 28 30 2e 38 2e  31 36 7e 65 78 70 35 75    .3 (0.8.16~exp5u
00528   62 75 6e 74 75 31 33 2e  36 29 0d 0a 0d 0a 47 45    buntu13.6)....GE
00544   54 20 2f 75 62 75 6e 74  75 2f 64 69 73 74 73 2f    T /ubuntu/dists/
00560   6f 6e 65 69 72 69 63 2d  75 70 64 61 74 65 73 2f    oneiric-updates/
00576   72 65 73 74 72 69 63 74  65 64 2f 69 31 38 6e 2f    restricted/i18n/
00592   54 72 61 6e 73 6c 61 74  69 6f 6e 2d 65 6e 2e 62    Translation-en.b
00608   7a 32 20 48 54 54 50 2f  31 2e 31 0d 0a 48 6f 73    z2 HTTP/1.1..Hos
00624   74 3a 20 75 73 2e 61 72  63 68 69 76 65 2e 75 62    t: us.archive.ub
00640   75 6e 74 75 2e 63 6f 6d  0d 0a 43 6f 6e 6e 65 63    untu.com..Connec
00656   74 69 6f 6e 3a 20 6b 65  65 70 2d 61 6c 69 76 65    tion: keep-alive
00672   0d 0a 43 61 63 68 65 2d  43 6f 6e 74 72 6f 6c 3a    ..Cache-Control:
00688   20 6d 61 78 2d 61 67 65  3d 30 0d 0a 49 66 2d 4d     max-age=0..If-M
00704   6f 64 69 66 69 65 64 2d  53 69 6e 63 65 3a 20 57    odified-Since: W
00720   65 64 2c 20 30 32 20 4d  61 79 20 32 30 31 32 20    ed, 02 May 2012 
00736   30 37 3a 32 37 3a 32 34  20 47 4d 54 0d 0a 55 73    07:27:24 GMT..Us
00752   65 72 2d 41 67 65 6e 74  3a 20 44 65 62 69 61 6e    er-Agent: Debian
00768   20 41 50 54 2d 48 54 54  50 2f 31 2e 33 20 28 30     APT-HTTP/1.3 (0
00784   2e 38 2e 31 36 7e 65 78  70 35 75 62 75 6e 74 75    .8.16~exp5ubuntu
00800   31 33 2e 36 29 0d 0a 0d  0a 47 45 54 20 2f 75 62    13.6)....GET /ub
00816   75 6e 74 75 2f 64 69 73  74 73 2f 6f 6e 65 69 72    untu/dists/oneir
00832   69 63 2d 75 70 64 61 74  65 73 2f 75 6e 69 76 65    ic-updates/unive
00848   72 73 65 2f 69 31 38 6e  2f 54 72 61 6e 73 6c 61    rse/i18n/Transla
00864   74 69 6f 6e 2d 65 6e 2e  62 7a 32 20 48 54 54 50    tion-en.bz2 HTTP
00880   2f 31 2e 31 0d 0a 48 6f  73 74 3a 20 75 73 2e 61    /1.1..Host: us.a
00896   72 63 68 69 76 65 2e 75  62 75 6e 74 75 2e 63 6f    rchive.ubuntu.co
00912   6d 0d 0a 43 6f 6e 6e 65  63 74 69 6f 6e 3a 20 6b    m..Connection: k
00928   65 65 70 2d 61 6c 69 76  65 0d 0a 43 61 63 68 65    eep-alive..Cache
00944   2d 43 6f 6e 74 72 6f 6c  3a 20 6d 61 78 2d 61 67    -Control: max-ag
00960   65 3d 30 0d 0a 49 66 2d  4d 6f 64 69 66 69 65 64    e=0..If-Modified
00976   2d 53 69 6e 63 65 3a 20  57 65 64 2c 20 31 39 20    -Since: Wed, 19 
00992   44 65 63 20 32 30 31 32  20 31 35 3a 30 39 3a 30    Dec 2012 15:09:0
01008   35 20 47 4d 54 0d 0a 55  73 65 72 2d 41 67 65 6e    5 GMT..User-Agen
01024   74 3a 20 44 65 62 69 61  6e 20 41 50 54 2d 48 54    t: Debian APT-HT
01040   54 50 2f 31 2e 33 20 28  30 2e 38 2e 31 36 7e 65    TP/1.3 (0.8.16~e
01056   78 70 35 75 62 75 6e 74  75 31 33 2e 36 29 0d 0a    xp5ubuntu13.6)..
01072   0d 0a 47 45 54 20 2f 75  62 75 6e 74 75 2f 64 69    ..GET /ubuntu/di
01088   73 74 73 2f 6f 6e 65 69  72 69 63 2d 62 61 63 6b    sts/oneiric-back
01104   70 6f 72 74 73 2f 6d 61  69 6e 2f 69 31 38 6e 2f    ports/main/i18n/
01120   54 72 61 6e 73 6c 61 74  69 6f 6e 2d 65 6e 2e 62    Translation-en.b
01136   7a 32 20 48 54 54 50 2f  31 2e 31 0d 0a 48 6f 73    z2 HTTP/1.1..Hos
01152   74 3a 20 75 73 2e 61 72  63 68 69 76 65 2e 75 62    t: us.archive.ub
01168   75 6e 74 75 2e 63 6f 6d  0d 0a 43 6f 6e 6e 65 63    untu.com..Connec
01184   74 69 6f 6e 3a 20 6b 65  65 70 2d 61 6c 69 76 65    tion: keep-alive
01200   0d 0a 43 61 63 68 65 2d  43 6f 6e 74 72 6f 6c 3a    ..Cache-Control:
01216   20 6d 61 78 2d 61 67 65  3d 30 0d 0a 49 66 2d 4d     max-age=0..If-M
01232   6f 64 69 66 69 65 64 2d  53 69 6e 63 65 3a 20 53    odified-Since: S
01248   61 74 2c 20 31 30 20 4d  61 72 20 32 30 31 32 20    at, 10 Mar 2012 
01264   30 37 3a 32 31 3a 33 33  20 47 4d 54 0d 0a 55 73    07:21:33 GMT..Us
01280   65 72 2d 41 67 65 6e 74  3a 20 44 65 62 69 61 6e    er-Agent: Debian
01296   20 41 50 54 2d 48 54 54  50 2f 31 2e 33 20 28 30     APT-HTTP/1.3 (0
01312   2e 38 2e 31 36 7e 65 78  70 35 75 62 75 6e 74 75    .8.16~exp5ubuntu
01328   31 33 2e 36 29 0d 0a 0d  0a 47 45 54 20 2f 75 62    13.6)....GET /ub
01344   75 6e 74 75 2f 64 69 73  74 73 2f 6f 6e 65 69 72    untu/dists/oneir
01360   69 63 2d 62 61 63 6b 70  6f 72 74 73 2f 6d 75 6c    ic-backports/mul
01376   74 69 76 65 72 73 65 2f  69 31 38 6e 2f 54 72 61    tiverse/i18n/Tra
01392   6e 73 6c 61 74 69 6f 6e  2d 65 6e 2e 62 7a 32 20    nslation-en.bz2 
01408   48 54 54 50 2f 31 2e 31  0d 0a 48 6f 73 74 3a 20    HTTP/1.1..Host: 
01424   75 73 2e 61 72 63 68 69  76 65 2e 75 62 75 6e 74    us.archive.ubunt
01440   75 2e 63 6f 6d 0d 0a 43                             u.com..C
2013-01-14 02:52:55.055695 00:0C:29:E9:94:8E -> C4:3D:C7:17:6F:9B type 0x800 len 760
192.168.0.200:54634 -> 91.189.91.14:80 TCP
00000   6f 6e 6e 65 63 74 69 6f  6e 3a 20 6b 65 65 70 2d    onnection: keep-
00016   61 6c 69 76 65 0d 0a 43  61 63 68 65 2d 43 6f 6e    alive..Cache-Con
00032   74 72 6f 6c 3a 20 6d 61  78 2d 61 67 65 3d 30 0d    trol: max-age=0.
00048   0a 49 66 2d 4d 6f 64 69  66 69 65 64 2d 53 69 6e    .If-Modified-Sin
00064   63 65 3a 20 4d 6f 6e 2c  20 32 34 20 4f 63 74 20    ce: Mon, 24 Oct 
00080   32 30 31 31 20 31 30 3a  32 31 3a 34 30 20 47 4d    2011 10:21:40 GM
00096   54 0d 0a 55 73 65 72 2d  41 67 65 6e 74 3a 20 44    T..User-Agent: D
00112   65 62 69 61 6e 20 41 50  54 2d 48 54 54 50 2f 31    ebian APT-HTTP/1
00128   2e 33 20 28 30 2e 38 2e  31 36 7e 65 78 70 35 75    .3 (0.8.16~exp5u
00144   62 75 6e 74 75 31 33 2e  36 29 0d 0a 0d 0a 47 45    buntu13.6)....GE
00160   54 20 2f 75 62 75 6e 74  75 2f 64 69 73 74 73 2f    T /ubuntu/dists/
00176   6f 6e 65 69 72 69 63 2d  62 61 63 6b 70 6f 72 74    oneiric-backport
00192   73 2f 72 65 73 74 72 69  63 74 65 64 2f 69 31 38    s/restricted/i18
00208   6e 2f 54 72 61 6e 73 6c  61 74 69 6f 6e 2d 65 6e    n/Translation-en
00224   2e 62 7a 32 20 48 54 54  50 2f 31 2e 31 0d 0a 48    .bz2 HTTP/1.1..H
00240   6f 73 74 3a 20 75 73 2e  61 72 63 68 69 76 65 2e    ost: us.archive.
00256   75 62 75 6e 74 75 2e 63  6f 6d 0d 0a 43 6f 6e 6e    ubuntu.com..Conn
00272   65 63 74 69 6f 6e 3a 20  6b 65 65 70 2d 61 6c 69    ection: keep-ali
00288   76 65 0d 0a 43 61 63 68  65 2d 43 6f 6e 74 72 6f    ve..Cache-Contro
00304   6c 3a 20 6d 61 78 2d 61  67 65 3d 30 0d 0a 49 66    l: max-age=0..If
00320   2d 4d 6f 64 69 66 69 65  64 2d 53 69 6e 63 65 3a    -Modified-Since:
00336   20 4d 6f 6e 2c 20 32 34  20 4f 63 74 20 32 30 31     Mon, 24 Oct 201
00352   31 20 31 30 3a 32 31 3a  34 30 20 47 4d 54 0d 0a    1 10:21:40 GMT..
00368   55 73 65 72 2d 41 67 65  6e 74 3a 20 44 65 62 69    User-Agent: Debi
00384   61 6e 20 41 50 54 2d 48  54 54 50 2f 31 2e 33 20    an APT-HTTP/1.3 
00400   28 30 2e 38 2e 31 36 7e  65 78 70 35 75 62 75 6e    (0.8.16~exp5ubun
00416   74 75 31 33 2e 36 29 0d  0a 0d 0a 47 45 54 20 2f    tu13.6)....GET /
00432   75 62 75 6e 74 75 2f 64  69 73 74 73 2f 6f 6e 65    ubuntu/dists/one
00448   69 72 69 63 2d 62 61 63  6b 70 6f 72 74 73 2f 75    iric-backports/u
00464   6e 69 76 65 72 73 65 2f  69 31 38 6e 2f 54 72 61    niverse/i18n/Tra
00480   6e 73 6c 61 74 69 6f 6e  2d 65 6e 2e 62 7a 32 20    nslation-en.bz2 
00496   48 54 54 50 2f 31 2e 31  0d 0a 48 6f 73 74 3a 20    HTTP/1.1..Host: 
00512   75 73 2e 61 72 63 68 69  76 65 2e 75 62 75 6e 74    us.archive.ubunt
00528   75 2e 63 6f 6d 0d 0a 43  6f 6e 6e 65 63 74 69 6f    u.com..Connectio
00544   6e 3a 20 6b 65 65 70 2d  61 6c 69 76 65 0d 0a 43    n: keep-alive..C
00560   61 63 68 65 2d 43 6f 6e  74 72 6f 6c 3a 20 6d 61    ache-Control: ma
00576   78 2d 61 67 65 3d 30 0d  0a 49 66 2d 4d 6f 64 69    x-age=0..If-Modi
00592   66 69 65 64 2d 53 69 6e  63 65 3a 20 4d 6f 6e 2c    fied-Since: Mon,
00608   20 31 35 20 4f 63 74 20  32 30 31 32 20 30 32 3a     15 Oct 2012 02:
00624   33 35 3a 32 31 20 47 4d  54 0d 0a 55 73 65 72 2d    35:21 GMT..User-
00640   41 67 65 6e 74 3a 20 44  65 62 69 61 6e 20 41 50    Agent: Debian AP
00656   54 2d 48 54 54 50 2f 31  2e 33 20 28 30 2e 38 2e    T-HTTP/1.3 (0.8.
00672   31 36 7e 65 78 70 35 75  62 75 6e 74 75 31 33 2e    16~exp5ubuntu13.
00688   36 29 0d 0a 0d 0a                                   6)....
2013-01-14 12:47:49.310903 C4:3D:C7:17:6F:9B -> 00:0C:29:E9:94:8E type 0x800 len 249
1.234.31.20:38720 -> 192.168.0.200:80 TCP
00000   47 45 54 20 2f 77 30 30  74 77 30 30 74 2e 61 74    GET /w00tw00t.at
00016   2e 62 6c 61 63 6b 68 61  74 73 2e 72 6f 6d 61 6e    .blackhats.roman
00032   69 61 6e 2e 61 6e 74 69  2d 73 65 63 3a 29 20 48    ian.anti-sec:) H
00048   54 54 50 2f 31 2e 31 0d  0a 41 63 63 65 70 74 3a    TTP/1.1..Accept:
00064   20 2a 2f 2a 0d 0a 41 63  63 65 70 74 2d 4c 61 6e     */*..Accept-Lan
00080   67 75 61 67 65 3a 20 65  6e 2d 75 73 0d 0a 41 63    guage: en-us..Ac
00096   63 65 70 74 2d 45 6e 63  6f 64 69 6e 67 3a 20 67    cept-Encoding: g
00112   7a 69 70 2c 20 64 65 66  6c 61 74 65 0d 0a 55 73    zip, deflate..Us
00128   65 72 2d 41 67 65 6e 74  3a 20 5a 6d 45 75 0d 0a    er-Agent: ZmEu..
00144   48 6f 73 74 3a 20 38 36  2e 30 2e 33 33 2e 32 30    Host: 86.0.33.20
00160   0d 0a 43 6f 6e 6e 65 63  74 69 6f 6e 3a 20 43 6c    ..Connection: Cl
00176   6f 73 65 0d 0a 0d 0a                                ose....
2013-01-14 12:47:54.817639 C4:3D:C7:17:6F:9B -> 00:0C:29:E9:94:8E type 0x800 len 236
1.234.31.20:42230 -> 192.168.0.200:80 TCP
00000   47 45 54 20 2f 70 68 70  4d 79 41 64 6d 69 6e 2f    GET /phpMyAdmin/
00016   73 63 72 69 70 74 73 2f  73 65 74 75 70 2e 70 68    scripts/setup.ph
00032   70 20 48 54 54 50 2f 31  2e 31 0d 0a 41 63 63 65    p HTTP/1.1..Acce
00048   70 74 3a 20 2a 2f 2a 0d  0a 41 63 63 65 70 74 2d    pt: */*..Accept-
00064   4c 61 6e 67 75 61 67 65  3a 20 65 6e 2d 75 73 0d    Language: en-us.
00080   0a 41 63 63 65 70 74 2d  45 6e 63 6f 64 69 6e 67    .Accept-Encoding
00096   3a 20 67 7a 69 70 2c 20  64 65 66 6c 61 74 65 0d    : gzip, deflate.
00112   0a 55 73 65 72 2d 41 67  65 6e 74 3a 20 5a 6d 45    .User-Agent: ZmE
00128   75 0d 0a 48 6f 73 74 3a  20 38 36 2e 30 2e 33 33    u..Host: 86.0.33
00144   2e 32 30 0d 0a 43 6f 6e  6e 65 63 74 69 6f 6e 3a    .20..Connection:
00160   20 43 6c 6f 73 65 0d 0a  0d 0a                       Close....
2013-01-14 12:48:00.827917 C4:3D:C7:17:6F:9B -> 00:0C:29:E9:94:8E type 0x800 len 236
1.234.31.20:45552 -> 192.168.0.200:80 TCP
00000   47 45 54 20 2f 70 68 70  6d 79 61 64 6d 69 6e 2f    GET /phpmyadmin/
00016   73 63 72 69 70 74 73 2f  73 65 74 75 70 2e 70 68    scripts/setup.ph
00032   70 20 48 54 54 50 2f 31  2e 31 0d 0a 41 63 63 65    p HTTP/1.1..Acce
00048   70 74 3a 20 2a 2f 2a 0d  0a 41 63 63 65 70 74 2d    pt: */*..Accept-
00064   4c 61 6e 67 75 61 67 65  3a 20 65 6e 2d 75 73 0d    Language: en-us.
00080   0a 41 63 63 65 70 74 2d  45 6e 63 6f 64 69 6e 67    .Accept-Encoding
00096   3a 20 67 7a 69 70 2c 20  64 65 66 6c 61 74 65 0d    : gzip, deflate.
00112   0a 55 73 65 72 2d 41 67  65 6e 74 3a 20 5a 6d 45    .User-Agent: ZmE
00128   75 0d 0a 48 6f 73 74 3a  20 38 36 2e 30 2e 33 33    u..Host: 86.0.33
00144   2e 32 30 0d 0a 43 6f 6e  6e 65 63 74 69 6f 6e 3a    .20..Connection:
00160   20 43 6c 6f 73 65 0d 0a  0d 0a                       Close....
2013-01-14 12:48:06.817903 C4:3D:C7:17:6F:9B -> 00:0C:29:E9:94:8E type 0x800 len 229
1.234.31.20:48734 -> 192.168.0.200:80 TCP
00000   47 45 54 20 2f 70 6d 61  2f 73 63 72 69 70 74 73    GET /pma/scripts
00016   2f 73 65 74 75 70 2e 70  68 70 20 48 54 54 50 2f    /setup.php HTTP/
00032   31 2e 31 0d 0a 41 63 63  65 70 74 3a 20 2a 2f 2a    1.1..Accept: */*
00048   0d 0a 41 63 63 65 70 74  2d 4c 61 6e 67 75 61 67    ..Accept-Languag
00064   65 3a 20 65 6e 2d 75 73  0d 0a 41 63 63 65 70 74    e: en-us..Accept
00080   2d 45 6e 63 6f 64 69 6e  67 3a 20 67 7a 69 70 2c    -Encoding: gzip,
00096   20 64 65 66 6c 61 74 65  0d 0a 55 73 65 72 2d 41     deflate..User-A
00112   67 65 6e 74 3a 20 5a 6d  45 75 0d 0a 48 6f 73 74    gent: ZmEu..Host
00128   3a 20 38 36 2e 30 2e 33  33 2e 32 30 0d 0a 43 6f    : 86.0.33.20..Co
00144   6e 6e 65 63 74 69 6f 6e  3a 20 43 6c 6f 73 65 0d    nnection: Close.
00160   0a 0d 0a                                            ...
2013-01-14 12:48:12.822560 C4:3D:C7:17:6F:9B -> 00:0C:29:E9:94:8E type 0x800 len 233
1.234.31.20:52079 -> 192.168.0.200:80 TCP
00000   47 45 54 20 2f 6d 79 61  64 6d 69 6e 2f 73 63 72    GET /myadmin/scr
00016   69 70 74 73 2f 73 65 74  75 70 2e 70 68 70 20 48    ipts/setup.php H
00032   54 54 50 2f 31 2e 31 0d  0a 41 63 63 65 70 74 3a    TTP/1.1..Accept:
00048   20 2a 2f 2a 0d 0a 41 63  63 65 70 74 2d 4c 61 6e     */*..Accept-Lan
00064   67 75 61 67 65 3a 20 65  6e 2d 75 73 0d 0a 41 63    guage: en-us..Ac
00080   63 65 70 74 2d 45 6e 63  6f 64 69 6e 67 3a 20 67    cept-Encoding: g
00096   7a 69 70 2c 20 64 65 66  6c 61 74 65 0d 0a 55 73    zip, deflate..Us
00112   65 72 2d 41 67 65 6e 74  3a 20 5a 6d 45 75 0d 0a    er-Agent: ZmEu..
00128   48 6f 73 74 3a 20 38 36  2e 30 2e 33 33 2e 32 30    Host: 86.0.33.20
00144   0d 0a 43 6f 6e 6e 65 63  74 69 6f 6e 3a 20 43 6c    ..Connection: Cl
00160   6f 73 65 0d 0a 0d 0a                                ose....
2013-01-14 12:48:18.817364 C4:3D:C7:17:6F:9B -> 00:0C:29:E9:94:8E type 0x800 len 233
1.234.31.20:55672 -> 192.168.0.200:80 TCP
00000   47 45 54 20 2f 4d 79 41  64 6d 69 6e 2f 73 63 72    GET /MyAdmin/scr
00016   69 70 74 73 2f 73 65 74  75 70 2e 70 68 70 20 48    ipts/setup.php H
00032   54 54 50 2f 31 2e 31 0d  0a 41 63 63 65 70 74 3a    TTP/1.1..Accept:
00048   20 2a 2f 2a 0d 0a 41 63  63 65 70 74 2d 4c 61 6e     */*..Accept-Lan
00064   67 75 61 67 65 3a 20 65  6e 2d 75 73 0d 0a 41 63    guage: en-us..Ac
00080   63 65 70 74 2d 45 6e 63  6f 64 69 6e 67 3a 20 67    cept-Encoding: g
00096   7a 69 70 2c 20 64 65 66  6c 61 74 65 0d 0a 55 73    zip, deflate..Us
00112   65 72 2d 41 67 65 6e 74  3a 20 5a 6d 45 75 0d 0a    er-Agent: ZmEu..
00128   48 6f 73 74 3a 20 38 36  2e 30 2e 33 33 2e 32 30    Host: 86.0.33.20
00144   0d 0a 43 6f 6e 6e 65 63  74 69 6f 6e 3a 20 43 6c    ..Connection: Cl
00160   6f 73 65 0d 0a 0d 0a 

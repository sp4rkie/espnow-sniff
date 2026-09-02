/*
 * espnow-inject - put a synthetic ESP-NOW action frame on the air through a monitor
 *                 mode interface, to self test espnow-sniff without pressing a button
 *
 * build: gcc -Wall -O2 -o espnow-inject espnow-inject.c
 *
 * frame layout produced here, which is what espnow-sniff expects to find:
 *
 *   radiotap(12) | 802.11 action hdr(24) | 7f 18 fe 34 | 4 random | dd LEN 18 fe 34 04 VER | payload
 *
 * the FCS is appended by the hardware, so it is not built here.
 *
 * THE DEFAULTS ARE DELIBERATELY INERT: both MACs are locally administered (02:...) so they
 * belong to no real device, and the payload is not a valid command. Aim this at a real
 * gateway MAC only if you actually want that gateway to act on the frame.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <signal.h>
#include <sys/socket.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <netpacket/packet.h>

#define MAX_PAYLOAD     250
#define FRAME_MAX       512

static volatile sig_atomic_t stop;

static void
on_int(int sig)
{
    (void)sig;
    stop = 1;
}

static int
parse_mac(const char *s, unsigned char *out)
{
    unsigned int b[6];
    int i;

    if (sscanf(s, "%x:%x:%x:%x:%x:%x", &b[0], &b[1], &b[2], &b[3], &b[4], &b[5]) != 6)
        return -1;
    for (i = 0; i < 6; i++) {
        if (b[i] > 0xff)
            return -1;
        out[i] = (unsigned char)b[i];
    }
    return 0;
}

static const char *
mac_str(const unsigned char *m)
{
    static char s[4][18];
    static int i;

    i = (i + 1) & 3;                    /* rotate: two calls can share one printf */
    snprintf(s[i], sizeof(s[i]), "%02x:%02x:%02x:%02x:%02x:%02x",
             m[0], m[1], m[2], m[3], m[4], m[5]);
    return s[i];
}

/*
 * read a small unsigned value out of /sys/class/net/<if>/<what>
 */
static long
sysnet(const char *ifn, const char *what)
{
    char path[256];
    FILE *f;
    long v;

    snprintf(path, sizeof(path), "/sys/class/net/%s/%s", ifn, what);
    if (!(f = fopen(path, "r")))
        return -1;
    if (fscanf(f, "%ld", &v) != 1)
        v = -1;
    fclose(f);
    return v;
}

static int
build(unsigned char *buf, const unsigned char *da, const unsigned char *sa,
      const unsigned char *bss, unsigned int seq, int rate, int ver,
      const unsigned char *pl, int plen)
{
    unsigned long r;
    int n = 0;

    /*
     * radiotap for injection: Rate (bit 2) and TX flags (bit 15) only.
     * rate sits at offset 8, then one pad byte so TX flags lands 2-aligned at 10.
     */
    buf[n++] = 0x00; buf[n++] = 0x00;                       /* it_version, it_pad */
    buf[n++] = 0x0c; buf[n++] = 0x00;                       /* it_len = 12 */
    buf[n++] = 0x04; buf[n++] = 0x80;                       /* it_present = 0x00008004 */
    buf[n++] = 0x00; buf[n++] = 0x00;
    buf[n++] = (unsigned char)rate;                         /* 500 kb/s units */
    buf[n++] = 0x00;                                        /* pad */
    buf[n++] = 0x08; buf[n++] = 0x00;                       /* TX flags: NOACK */

    buf[n++] = 0xd0; buf[n++] = 0x00;                       /* frame control: mgmt / action */
    buf[n++] = 0x00; buf[n++] = 0x00;                       /* duration */
    memcpy(buf + n, da,  6); n += 6;
    memcpy(buf + n, sa,  6); n += 6;
    memcpy(buf + n, bss, 6); n += 6;
    buf[n++] = (unsigned char)((seq << 4) & 0xff);          /* sequence control */
    buf[n++] = (unsigned char)((seq >> 4) & 0xff);

    buf[n++] = 0x7f;                                        /* category: vendor specific */
    buf[n++] = 0x18; buf[n++] = 0xfe; buf[n++] = 0x34;      /* Espressif OUI */

    r = (unsigned long)random();
    buf[n++] = (unsigned char)(r         & 0xff);           /* the 4 random bytes */
    buf[n++] = (unsigned char)((r >>  8) & 0xff);
    buf[n++] = (unsigned char)((r >> 16) & 0xff);
    buf[n++] = (unsigned char)((r >> 24) & 0xff);

    buf[n++] = 0xdd;                                        /* vendor specific element */
    buf[n++] = (unsigned char)(5 + plen);
    buf[n++] = 0x18; buf[n++] = 0xfe; buf[n++] = 0x34;
    buf[n++] = 0x04;                                        /* type: ESP-NOW */
    buf[n++] = (unsigned char)ver;
    memcpy(buf + n, pl, plen); n += plen;

    return n;
}

static void
usage(const char *prog)
{
    fprintf(stderr,
        "usage: %s [options]\n\n"
        "  -i MONIF   monitor interface to transmit on             [mon0]\n"
        "  -c COUNT   frames to send (0 = forever)                 [5]\n"
        "  -d MS      delay between frames, milliseconds           [500]\n"
        "  -s MAC     source address                               [02:00:00:00:00:01]\n"
        "  -a MAC     destination address                          [02:00:00:00:00:02]\n"
        "  -b MAC     BSSID                                        [ff:ff:ff:ff:ff:ff]\n"
        "  -p TEXT    payload text, a NUL is appended              [ESPNOW-SELFTEST]\n"
        "  -V VER     ESP-NOW version byte                         [1]\n"
        "  -r RATE    tx rate in 500 kb/s units (2 = 1.0 Mb/s)     [2]\n"
        "  -N         do not append the trailing NUL\n"
        "  -h         this help\n\n"
        "  %s -i mon0 -c 5\n"
        "  %s -i mon0 -c 0 -d 200 -p \"hello from e0\"\n",
        prog, prog, prog);
    exit(1);
}

int
main(int argc, char **argv)
{
    unsigned char da[6], sa[6], bss[6], pl[MAX_PAYLOAD + 1], buf[FRAME_MAX];
    struct sockaddr_ll sll;
    struct timespec ts;
    const char *ifn = "mon0", *text = "ESPNOW-SELFTEST";
    long ifidx, iftype;
    int count = 5, delay = 500, ver = 1, rate = 2, nonul = 0;
    int fd, len, plen, sent = 0;
    unsigned int seq;
    int c;

    parse_mac("02:00:00:00:00:01", sa);
    parse_mac("02:00:00:00:00:02", da);
    parse_mac("ff:ff:ff:ff:ff:ff", bss);

    while ((c = getopt(argc, argv, "i:c:d:s:a:b:p:V:r:Nh")) != -1) {
        switch (c) {
        case 'i': ifn = optarg; break;
        case 'c': count = atoi(optarg); break;
        case 'd': delay = atoi(optarg); break;
        case 'p': text = optarg; break;
        case 'V': ver = atoi(optarg); break;
        case 'r': rate = atoi(optarg); break;
        case 'N': nonul = 1; break;
        case 's':
            if (parse_mac(optarg, sa) < 0) { fprintf(stderr, "bad MAC '%s'\n", optarg); return 1; }
            break;
        case 'a':
            if (parse_mac(optarg, da) < 0) { fprintf(stderr, "bad MAC '%s'\n", optarg); return 1; }
            break;
        case 'b':
            if (parse_mac(optarg, bss) < 0) { fprintf(stderr, "bad MAC '%s'\n", optarg); return 1; }
            break;
        default:
            usage(argv[0]);
        }
    }

    plen = (int)strlen(text) + (nonul ? 0 : 1);
    if (plen > MAX_PAYLOAD) {
        fprintf(stderr, "%s: payload too long (%d > %d)\n", argv[0], plen, MAX_PAYLOAD);
        return 1;
    }
    memcpy(pl, text, strlen(text));
    if (!nonul)
        pl[strlen(text)] = 0;

    /*
     * refuse to be surprising: a destination that is neither broadcast nor locally
     * administered belongs to a real device, which may well act on the frame
     */
    if (memcmp(da, "\xff\xff\xff\xff\xff\xff", 6) && !(da[0] & 0x02))
        fprintf(stderr, "%s: WARNING %s is a real (globally administered) MAC -\n"
                        "%s:         that device may act on this frame\n",
                argv[0], mac_str(da), argv[0]);

    if ((ifidx = sysnet(ifn, "ifindex")) < 0) {
        fprintf(stderr, "%s: no such interface '%s' - create it with:\n"
                        "         iw phy phyN interface add %s type monitor flags none\n",
                argv[0], ifn, ifn);
        return 1;
    }
    if ((iftype = sysnet(ifn, "type")) != ARPHRD_IEEE80211_RADIOTAP) {
        fprintf(stderr, "%s: '%s' is type %ld, need %d (monitor/radiotap)\n",
                argv[0], ifn, iftype, ARPHRD_IEEE80211_RADIOTAP);
        return 1;
    }

    if ((fd = socket(AF_PACKET, SOCK_RAW, 0)) < 0) {
        fprintf(stderr, "%s: socket: %s\n", argv[0], strerror(errno));
        return 1;
    }
    memset(&sll, 0, sizeof(sll));
    sll.sll_family  = AF_PACKET;
    sll.sll_ifindex = (int)ifidx;
    sll.sll_halen   = 0;
    if (bind(fd, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
        fprintf(stderr, "%s: bind %s: %s\n", argv[0], ifn, strerror(errno));
        return 1;
    }

    signal(SIGINT, on_int);
    srandom((unsigned int)(time(0) ^ getpid()));
    seq = (unsigned int)(random() & 0xfff);

    fprintf(stderr, "%s: %s (ifindex %ld), %s -> %s, %d byte payload \"%s\"\n",
            argv[0], ifn, ifidx, mac_str(sa), mac_str(da), plen, text);

    while (!stop && (count == 0 || sent < count)) {
        len = build(buf, da, sa, bss, seq, rate, ver, pl, plen);
        if (send(fd, buf, len, 0) < 0) {
            fprintf(stderr, "%s: send: %s\n", argv[0], strerror(errno));
            return 1;
        }
        sent++;
        seq = (seq + 1) & 0xfff;

        if (!stop && (count == 0 || sent < count)) {
            ts.tv_sec  = delay / 1000;
            ts.tv_nsec = (long)(delay % 1000) * 1000000L;
            nanosleep(&ts, 0);
        }
    }

    fprintf(stderr, "%s: %d frame(s) sent\n", argv[0], sent);
    close(fd);
    return 0;
}

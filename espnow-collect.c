/*
 * espnow-collect - accept pcap streams from several ESP-NOW sniffers and file them per source
 *
 * Each sniffer (see esp32-sniffer / ultra_espnow_sniff) connects and streams a plain pcap of
 * everything it heard. This listens, accepts as many of them as you care to deploy, and
 * appends each one's stream to its own file named after the peer.
 *
 * Appending across reconnects is safe: a sniffer re-emits the pcap global header every time
 * it connects, and espnow-sniff skips headers repeated mid-stream.
 *
 *   espnow-collect -d /var/lib/espnow &
 *   espnow-sniff -r /var/lib/espnow/espnow-10.0.0.5.pcap          # one collector, so far
 *   tail -c +1 -f /var/lib/espnow/espnow-10.0.0.5.pcap | espnow-sniff -r /dev/stdin   # live
 *
 * build: gcc -Wall -O2 -o espnow-collect espnow-collect.c
 */

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <signal.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define MAXC        32                  /* collectors we will hold at once */
#define BUFSZ       8192

struct client {
    int             fd;
    FILE           *f;
    char            ip[INET_ADDRSTRLEN];
    unsigned long   bytes;
    time_t          since;
};

static struct client cl[MAXC];
static volatile sig_atomic_t stop;
static int quiet;

static void
on_sig(int sig)
{
    (void)sig;
    stop = 1;
}

static void
logf_(const char *fmt, ...)
{
    va_list ap;
    char ts[32];
    time_t now = time(0);

    if (quiet)
        return;
    strftime(ts, sizeof(ts), "%H:%M:%S", localtime(&now));
    fprintf(stderr, "%s espnow-collect: ", ts);
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
    fflush(stderr);
}

static void
drop(struct client *c)
{
    logf_("%s closed after %lu bytes in %lds", c->ip, c->bytes, (long)(time(0) - c->since));
    if (c->f)
        fclose(c->f);
    close(c->fd);
    memset(c, 0, sizeof(*c));
    c->fd = -1;
}

static void
usage(const char *prog)
{
    fprintf(stderr,
        "usage: %s [options]\n\n"
        "  -p PORT    port to listen on                    [5555]\n"
        "  -d DIR     directory for the per source files   [.]\n"
        "  -q         no connect/disconnect logging\n"
        "  -h         this help\n\n"
        "  each source is appended to DIR/espnow-<ip>.pcap\n", prog);
    exit(1);
}

int
main(int argc, char **argv)
{
    struct pollfd pfd[MAXC + 1];
    struct sockaddr_in sa;
    const char *dir = ".";
    int port = 5555, srv, one = 1, i, n, c;
    char buf[BUFSZ], path[512];

    while ((c = getopt(argc, argv, "p:d:qh")) != -1) {
        switch (c) {
        case 'p': port = atoi(optarg); break;
        case 'd': dir = optarg; break;
        case 'q': quiet = 1; break;
        default:  usage(argv[0]);
        }
    }

    for (i = 0; i < MAXC; i++)
        cl[i].fd = -1;

    if (mkdir(dir, 0755) < 0 && errno != EEXIST) {
        fprintf(stderr, "%s: %s: %s\n", argv[0], dir, strerror(errno));
        return 1;
    }

    if ((srv = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        fprintf(stderr, "%s: socket: %s\n", argv[0], strerror(errno));
        return 1;
    }
    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    memset(&sa, 0, sizeof(sa));
    sa.sin_family      = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_ANY);
    sa.sin_port        = htons(port);
    if (bind(srv, (struct sockaddr *)&sa, sizeof(sa)) < 0 || listen(srv, 8) < 0) {
        fprintf(stderr, "%s: bind/listen %d: %s\n", argv[0], port, strerror(errno));
        return 1;
    }

    signal(SIGINT,  on_sig);
    signal(SIGTERM, on_sig);
    signal(SIGPIPE, SIG_IGN);

    logf_("listening on port %d, writing to %s", port, dir);

    while (!stop) {
        n = 0;
        pfd[n].fd = srv; pfd[n].events = POLLIN; n++;
        for (i = 0; i < MAXC; i++)
            if (cl[i].fd >= 0) {
                pfd[n].fd = cl[i].fd;
                pfd[n].events = POLLIN;
                pfd[n].revents = 0;
                n++;
            }

        if (poll(pfd, n, 1000) < 0) {
            if (errno == EINTR)
                continue;
            break;
        }

        if (pfd[0].revents & POLLIN) {
            struct sockaddr_in pa;
            socklen_t pl = sizeof(pa);
            int fd = accept(srv, (struct sockaddr *)&pa, &pl);

            if (fd >= 0) {
                for (i = 0; i < MAXC && cl[i].fd >= 0; i++)
                    ;
                if (i == MAXC) {
                    logf_("no free slot, refusing a connection");
                    close(fd);
                } else {
                    cl[i].fd = fd;
                    cl[i].bytes = 0;
                    cl[i].since = time(0);
                    inet_ntop(AF_INET, &pa.sin_addr, cl[i].ip, sizeof(cl[i].ip));
                    snprintf(path, sizeof(path), "%s/espnow-%s.pcap", dir, cl[i].ip);
                    if (!(cl[i].f = fopen(path, "ab"))) {
                        logf_("%s: %s", path, strerror(errno));
                        close(fd);
                        cl[i].fd = -1;
                    } else
                        logf_("%s connected -> %s", cl[i].ip, path);
                }
            }
        }

        /*
         * walk the poll results back onto the client table. the order is the same as it
         * was built above, so a second pass over the live entries lines them up
         */
        n = 1;
        for (i = 0; i < MAXC; i++) {
            if (cl[i].fd < 0)
                continue;
            if (pfd[n].revents & (POLLIN | POLLHUP | POLLERR)) {
                int r = read(cl[i].fd, buf, sizeof(buf));

                if (r <= 0)
                    drop(&cl[i]);
                else {
                    fwrite(buf, 1, r, cl[i].f);
                    fflush(cl[i].f);            /* a reader may be tailing the file */
                    cl[i].bytes += r;
                }
            }
            n++;
        }
    }

    for (i = 0; i < MAXC; i++)
        if (cl[i].fd >= 0)
            drop(&cl[i]);
    close(srv);
    logf_("stopped");
    return 0;
}

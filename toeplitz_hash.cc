#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#define V4_PACKET_BYTE_SIZE 12
#define V4_PACKET_BYTE_SIZE_TCP 12
#define V4_PACKET_BYTE_SIZE_NO_TCP 8

#define V4_WITH_TCP 12
#define V4_WITHOUT_TCP 8

#define V6_PACKET_BYTE_SIZE 36
#define V6_PACKET_BYTE_SIZE_TCP 36
#define V6_PACKET_BYTE_SIZE_NO_TCP 32

#define V6_WITH_TCP 36
#define V6_WITHOUT_TCP 32

#define RANDOM_KEY_SIZE 40

typedef union {
    uint8_t u8[RANDOM_KEY_SIZE];
    uint32_t u32[10];
} rss_key;

static const rss_key random_key = {
    .u8 = {
        0x6d, 0x5a, 0x56, 0xda, 0x25, 0x5b, 0x0e, 0xc2, 0x41, 0x67,
        0x25, 0x3d, 0x43, 0xa3, 0x8f, 0xb0, 0xd0, 0xca, 0x2b, 0xcb,
        0xae, 0x7b, 0x30, 0xb4, 0x77, 0xcb, 0x2d, 0xa3, 0x80, 0x30,
        0xf2, 0x0c, 0x6a, 0x42, 0xb7, 0x3b, 0xbe, 0xac, 0x01, 0xfa,
    }};

typedef struct verification_table {
    char src_addr[40];
    char dst_addr[40];
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t with_tcp_hash;
    uint32_t without_tcp_hash;
    int protocol;
} vt_t;

static const struct verification_table table[8] = {
    {
        .src_addr         = "66.9.149.187",
        .dst_addr         = "161.142.100.80",
        .src_port         = 2794,
        .dst_port         = 1766,
        .with_tcp_hash    = 0x51ccc178,
        .without_tcp_hash = 0x323e8fc2,
        .protocol         = AF_INET,
    },
    {
        .src_addr         = "199.92.111.2",
        .dst_addr         = "65.69.140.83",
        .src_port         = 14230,
        .dst_port         = 4739,
        .with_tcp_hash    = 0xc626b0ea,
        .without_tcp_hash = 0xd718262a,
        .protocol         = AF_INET,
    },
    {
        .src_addr         = "24.19.198.95",
        .dst_addr         = "12.22.207.184",
        .src_port         = 12898,
        .dst_port         = 38024,
        .with_tcp_hash    = 0x5c2b394a,
        .without_tcp_hash = 0xd2d0a5de,
        .protocol         = AF_INET,
    },
    {
        .src_addr         = "38.27.205.30",
        .dst_addr         = "209.142.163.6",
        .src_port         = 48228,
        .dst_port         = 2217,
        .with_tcp_hash    = 0xafc7327f,
        .without_tcp_hash = 0x82989176,
        .protocol         = AF_INET,
    },
    {
        .src_addr         = "153.39.163.191",
        .dst_addr         = "202.188.127.2",
        .src_port         = 44251,
        .dst_port         = 1303,
        .with_tcp_hash    = 0x10e828a2,
        .without_tcp_hash = 0x5d1809c5,
        .protocol         = AF_INET,
    },
    // ==============================================================
    // IPv6
    // ==============================================================
    {
        .src_addr         = "3ffe:2501:200:1fff::7",
        .dst_addr         = "3ffe:2501:200:3::1",
        .src_port         = 2794,
        .dst_port         = 1766,
        .with_tcp_hash    = 0x40207d3d,
        .without_tcp_hash = 0x2cc18cd5,
        .protocol         = AF_INET6,
    },
    {
        .src_addr         = "3ffe:501:8::260:97ff:fe40:efab",
        .dst_addr         = "ff02::1",
        .src_port         = 14230,
        .dst_port         = 4739,
        .with_tcp_hash    = 0xdde51bbf,
        .without_tcp_hash = 0x0f0c461c,
        .protocol         = AF_INET6,
    },
    {
        .src_addr         = "3ffe:1900:4545:3:200:f8ff:fe21:67cf",
        .dst_addr         = "fe80::200:f8ff:fe21:67cf",
        .src_port         = 44251,
        .dst_port         = 38024,
        .with_tcp_hash    = 0x02d1feef,
        .without_tcp_hash = 0x4b61e985,
        .protocol         = AF_INET6,
    },
};

void create_binary(void *packet,
                   void *src_addr,
                   void *dst_addr,
                   uint16_t src_port,
                   uint16_t dst_port,
                   int protocol) {

    if (protocol == AF_INET) {
        uint8_t *p      = (uint8_t *) packet;
        uint32_t *saddr = (uint32_t *) src_addr;
        uint32_t *daddr = (uint32_t *) dst_addr;

        *saddr = htonl(*saddr);
        *daddr = htonl(*daddr);

        p[0] = (*saddr & 0xff000000) >> 24;
        p[1] = (*saddr & 0x00ff0000) >> 16;
        p[2] = (*saddr & 0x0000ff00) >> 8;
        p[3] = (*saddr & 0x000000ff);

        p[4] = (*daddr & 0xff000000) >> 24;
        p[5] = (*daddr & 0x00ff0000) >> 16;
        p[6] = (*daddr & 0x0000ff00) >> 8;
        p[7] = (*daddr & 0x000000ff);

        p[8]  = (src_port & 0xff00) >> 8;
        p[9]  = (src_port & 0x00ff);
        p[10] = (dst_port & 0xff00) >> 8;
        p[11] = (dst_port & 0x00ff);
    } else {

        uint8_t *p = (uint8_t *) packet;

        uint32_t *saddr = (uint32_t *) src_addr;
        uint32_t *daddr = (uint32_t *) dst_addr;

        uint32_t tmp;

        for (int i = 0, j = 0; i < 16; i++) {
            if (0 < i && i % 4 == 0) {
                j++;
            }
            tmp  = htonl(saddr[j]);
            p[i] = tmp >> (24 - (8 * (i % 4)));
        }
        for (int i = 16, j = 0; i < 32; i++) {
            if (16 < i && i % 4 == 0) {
                j++;
            }
            tmp  = htonl(daddr[j]);
            p[i] = tmp >> (24 - (8 * (i % 4)));
        }

        p[32] = (src_port & 0xff00) >> 8;
        p[33] = (src_port & 0x00ff);
        p[34] = (dst_port & 0xff00) >> 8;
        p[35] = (dst_port & 0x00ff);
    }
}

void print_packet(void *packet, int protocol) {
    int size;
    size = protocol == AF_INET ? V4_PACKET_BYTE_SIZE : V6_PACKET_BYTE_SIZE;

    uint8_t *p = (uint8_t *) packet;
    for (int i = 0; i < size; i++) {
        printf("0x%02x ", p[i]);
    }
    puts("");
}

uint32_t compute_hash(void *packet, uint32_t N) {
    uint8_t *p = (uint8_t *) packet;

    uint32_t ret;

    uint32_t key = (random_key.u8[0] << 24) | (random_key.u8[1] << 16) |
                   (random_key.u8[2] << 8) | random_key.u8[3];

    ret = 0;
    for (int i = 0; i < N; i++) {
        for (int j = 0; j < 8; j++) {
            if (p[i] & (1 << (7 - j))) {
                ret ^= key;
            }
            key <<= 1;
            if ((i + 4) < RANDOM_KEY_SIZE &&
                (random_key.u8[i + 4] & (1 << (7 - j)))) {
                key |= 1;
            }
        }
    }

    return ret;
}

void convert_inet_pton(void *dst, const char *caddr, int protocol) {
    int ret;

    ret = inet_pton(protocol, caddr, dst);
    if (ret == 0) {
        fprintf(stderr, "error inet_pton %s\n", caddr);
        goto err;
    }
    *(uint32_t *) dst = *(uint32_t *) dst;
    return;

err:
    exit(EXIT_FAILURE);
}

void setup_vfmrqc(uint8_t rxq, uint8_t *rss_indir_tbl) {
    uint32_t vfmrqc = 0, vfreta = 0;
    uint16_t rss_i = rxq;
    uint8_t i, j;

    for (i = 0, j = 0; i < 64; i++, j++) {
        if (j == rss_i) j = 0;

        rss_indir_tbl[i] = j;
        printf("indir_tbl[%d]=%d\n", i, j);

        vfreta |= j << (i & 0x3) * 8;
        if ((i & 3) == 3) {
            // set32(_map, IXGBE_VFRETA(i >> 2), vfreta);
            // printf("i(%d) j(%d) 0x%08x\n", i, j, vfreta);
            vfreta = 0;
        }
    }
}

int main(void) {
    uint32_t v4_src_addr;
    uint32_t v4_dst_addr;
    struct in6_addr v6_src_addr;
    struct in6_addr v6_dst_addr;

    uint8_t ipv4_packet[V4_PACKET_BYTE_SIZE];
    uint8_t ipv6_packet[V6_PACKET_BYTE_SIZE];

    uint8_t rss_indir_tbl[64];

    int rss_enabled;
    uint8_t cpu_index_mask;

    rss_enabled = 1;

    cpu_index_mask = rss_enabled ? 0x3 : 0;

    setup_vfmrqc(2, rss_indir_tbl);
    for (int i = 0; i < 8; i++) {
        const struct verification_table *vt = &table[i];
        void *saddr, *daddr;
        void *packet;
        uint16_t sport, dport, protocol;
        int with_tcp_len, without_tcp_len;

        if (vt->protocol == AF_INET) {
            saddr           = &v4_src_addr;
            daddr           = &v4_dst_addr;
            packet          = ipv4_packet;
            with_tcp_len    = V4_WITH_TCP;
            without_tcp_len = V4_WITHOUT_TCP;
        } else {
            saddr           = &v6_src_addr;
            daddr           = &v6_dst_addr;
            packet          = ipv6_packet;
            with_tcp_len    = V6_WITH_TCP;
            without_tcp_len = V6_WITHOUT_TCP;
        }
        sport    = vt->src_port;
        dport    = vt->dst_port;
        protocol = vt->protocol;

        convert_inet_pton(saddr, vt->src_addr, protocol);
        convert_inet_pton(daddr, vt->dst_addr, protocol);

        create_binary(packet, saddr, daddr, sport, dport, protocol);

        printf("[DST]=%-*s(%*d) [SRC]=%-*s(%*d)  [WITH STATE]=",
               25,
               vt->dst_addr,
               5,
               vt->dst_port,
               36,
               vt->src_addr,
               5,
               vt->src_port);

        uint32_t hash;
        hash = compute_hash(packet, with_tcp_len);
        if (hash == vt->with_tcp_hash) {
            printf("OK ");
        } else {
            printf("NG return(0x%08x)\n", hash);
            exit(EXIT_FAILURE);
        }
        printf("[WITHOUT STATE]=");
        hash = compute_hash(packet, without_tcp_len);
        if (hash == vt->without_tcp_hash) {
            printf("OK  ");
        } else {
            printf("NG [return]=0x%08x\n", hash);
            exit(EXIT_FAILURE);
        }

        uint8_t cpu_idx;
        cpu_idx = rss_indir_tbl[hash & 0x0000003f] & cpu_index_mask;
        printf("[CPU INDEX]=%d\n", cpu_idx);
    }

    return 0;
}

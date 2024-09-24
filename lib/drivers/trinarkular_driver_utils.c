/*
 * This source code is Copyright (c) 2024 Georgia Tech Research Corporation. All
 * Rights Reserved. Permission to copy, modify, and distribute this software and
 * its documentation for academic research and education purposes, without fee,
 * and without a written agreement is hereby granted, provided that the above
 * copyright notice, this paragraph and the following three paragraphs appear in
 * all copies. Permission to make use of this software for other than academic
 * research and education purposes may be obtained by contacting:
 *
 *  Office of Technology Licensing
 *  Georgia Institute of Technology
 *  926 Dalney Street, NW
 *  Atlanta, GA 30318
 *  404.385.8066
 *  techlicensing@gtrc.gatech.edu
 *
 * This software program and documentation are copyrighted by Georgia Tech
 * Research Corporation (GTRC). The software program and documentation are 
 * supplied "as is", without any accompanying services from GTRC. GTRC does
 * not warrant that the operation of the program will be uninterrupted or
 * error-free. The end-user understands that the program was developed for
 * research purposes and is advised not to rely exclusively on the program for
 * any reason.
 *
 * IN NO EVENT SHALL GEORGIA TECH RESEARCH CORPORATION BE LIABLE TO ANY PARTY FOR
 * DIRECT, INDIRECT, SPECIAL, INCIDENTAL, OR CONSEQUENTIAL DAMAGES, INCLUDING
 * LOST PROFITS, ARISING OUT OF THE USE OF THIS SOFTWARE AND ITS DOCUMENTATION,
 * EVEN IF GEORGIA TECH RESEARCH CORPORATION HAS BEEN ADVISED OF THE POSSIBILITY
 * OF SUCH DAMAGE. GEORGIA TECH RESEARCH CORPORATION SPECIFICALLY DISCLAIMS ANY
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE. THE SOFTWARE PROVIDED
 * HEREUNDER IS ON AN "AS IS" BASIS, AND  GEORGIA TECH RESEARCH CORPORATION HAS
 * NO OBLIGATIONS TO PROVIDE MAINTENANCE, SUPPORT, UPDATES, ENHANCEMENTS, OR
 * MODIFICATIONS.
 *
 * This source code is part of the trinarkular software. The original trinarkular
 * software is Copyright (c) 2015 The Regents of the University of California.
 * All rights reserved. Permission to copy, modify, and distribute this software
 * for academic research and education purposes is subject to the conditions and
 * copyright notices in the source code files and in the included LICENSE file.
 */

#include "config.h"
#include <limits.h>
#include <sys/socket.h>
#include <ctype.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include <inttypes.h>
#include <fcntl.h>
#include <stdlib.h>

/* Reimplementation of various scamper utility functions that
 * trinarkular uses that are now no longer available as external
 * symbols in more recent versions of libscamper.
 */

int sockaddr_compose(struct sockaddr *sa, int af, const void *addr, int port) {
    socklen_t len;
    struct sockaddr_in *sin4;
    struct sockaddr_in6 *sin6;

    if (port < 0 || port > 65535) {
        return -1;
    }

    if (af == AF_INET) {
        len = sizeof(struct sockaddr_in);
        memset(sa, 0, len);
        sin4 = (struct sockaddr_in *)sa;
        if (addr != NULL) {
            memcpy(&sin4->sin_addr, addr, sizeof(struct in_addr));
        }
        sin4->sin_port = htons(port);
    } else if (af == AF_INET6) {
        len = sizeof(struct sockaddr_in6);
        memset(sa, 0, len);
        sin6 = (struct sockaddr_in6 *)sa;
        if (addr != NULL) {
            memcpy(&sin6->sin6_addr, addr, sizeof(struct in6_addr));
        }
        sin6->sin6_port = htons(port);
    } else {
        return -1;
    }

    sa->sa_family = af;
    return 0;
}

/*
 * Decodes four ascii characters to produce up to 3 binary bytes.
 */
static int uudecode_4bytes(uint8_t *out, const char *in, size_t c)
{
    char a, b;

    if (c == 0) {
        return -1;
    }

    if (in[0] >= '!' && in[0] <= '`') {
        a = in[0];
    } else {
        return -1;
    }

    if (in[1] >= '!' && in[1] <= '`') {
        b = in[1];
    } else {
        return -1;
    }

    out[0] = (((a - 32) & 0x3f) << 2 & 0xfc) | (((b - 32) & 0x3f) >> 4 & 0x3);

    if (in[2] >= '!' && in[2] <= '`') {
        a = in[2];
    } else {
        return -1;
    }

    if (c > 1) {
        out[1] = (((b - 32) & 0x3f) << 4 & 0xf0) |
            (((a - 32) & 0x3f) >> 2 & 0xf);
    }

    if (in[3] >= '!' && in[3] <= '`') {
        b = in[3];
    } else {
        return -1;
    }

    if (c > 2) {
        out[2] = (((a - 32) & 0x3f) << 6 & 0xc0) |  ((b - 32) & 0x3f);
    }

    return 0;
}

int uudecode_line(const char *in, size_t ilen, uint8_t *out, size_t *olen) {
    size_t i, j, o;

    i = 0;
    j = 1;

    if (ilen == 0) {
        goto err;
    }

    /* EOF */
    if (in[0] == '`') {
        *olen = 0;
        return 0;
    }

    /* Determine the number of binary bytes that should be found */
    if (in[0] >= '!' && in[0] <= '`') {
        o = in[0] - 32;
    } else {
        goto err;
    }

    /* Make sure we have enough space to uudecode */
    if (o > *olen) {
        goto err;
    }

    while(1) {
        /* There needs to be at least four characters remaining */
        if (ilen - j < 4) {
            goto err;
        }

        /* Decode 4 characters into 3 bytes */
        if (uudecode_4bytes(out+i, in+j, o-i) != 0) {
            goto err;
        }

        /* Move to the next block of 4 characters */
        j += 4;

        /* Advance the output pointer */
        if (o-i > 3) {
            i += 3;
        } else {
            /* No more space */
            break;
        }
    }

    *olen = o;
    return 0;

err:
    return -1;
}

int fcntl_set(int fd, int flags) {
    int i;

    if ((i = fcntl(fd, F_GETFL, 0)) == -1) {
        return -1;
    }

    if (fcntl(fd, F_SETFL, i | flags) == -1) {
        return -1;
    }

    return 0;
}

int string_tolong(const char *str, long *l) {
    char *endptr;

    errno = 0;
    *l = strtol(str, &endptr, 0);
    if (*l == 0) {
        if (errno == EINVAL || endptr == str) {
            return -1;
        }
    } else if (*l == LONG_MIN || *l == LONG_MAX) {
        if(errno == ERANGE) {
            return -1;
        }
    }

    return 0;
}

int string_isnumber(const char *str) {
    int i = 1;

    if (str[0] != '-' && str[0] != '+' && isdigit((unsigned char)str[0]) == 0) {
        return 0;
    }

    while(str[i] != '\0') {
        if (isdigit((unsigned char)str[i]) != 0) {
            i++;
            continue;
        }

        return 0;
    }

    return 1;
}


/*
 * Copyright (C) 2016 Antoine Tenart <antoine.tenart@ack.tf>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/*
 * SSHGuard. See http://www.sshguard.net
 */
#ifndef COMMAND_H
#define COMMAND_H

#include "../config.h"

#define QUOTEME_(x)     #x
#define QUOTEME(x)      QUOTEME_(x)

#define NFT_CMD         NFT_PATH "/nft "

#define COMMAND_INIT    NFT_CMD "add table inet sshguard && " \
                        NFT_CMD "add chain inet sshguard input { type filter hook input priority 0 \\; policy accept \\; }"
#define COMMAND_FIN     NFT_CMD "delete table inet sshguard"

#define COMMAND_BLOCK   "FAM=\"ip\"; [ x$SSHG_ADDRKIND == x6 ] && FAM=\"ip6\";" \
                        NFT_CMD "add rule inet sshguard input $FAM saddr $SSHG_ADDR drop"
/* Upstream rule deletion currently only works by handle */
#define COMMAND_RELEASE NFT_CMD "delete rule inet sshguard input handle " \
                        "$(" NFT_CMD " list table inet sshguard -a -n | " QUOTEME(EGREP) " $SSHG_ADDR | " QUOTEME(AWK) " -F' ' '{print $NF}')"

#define COMMAND_FLUSH   NFT_CMD "flush table inet sshguard"

#endif

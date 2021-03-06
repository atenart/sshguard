/*
 * Copyright (c) 2007,2008,2009 Mij <mij@sshguard.net>
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

#define COMMAND_INIT    ""
#define COMMAND_FIN     ""

#define COMMAND_BLOCK   PFCTL_PATH "/pfctl -k $SSHG_ADDR -t sshguard -T add $SSHG_ADDR"
#define COMMAND_RELEASE PFCTL_PATH "/pfctl -t sshguard -T del $SSHG_ADDR"

#define COMMAND_FLUSH   PFCTL_PATH "/pfctl -t sshguard -T flush"

#endif

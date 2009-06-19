/*
 * Copyright (c) 2007,2008 Mij <mij@bitchx.it>
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
 * SSHGuard. See http://sshguard.sourceforge.net
 */


#ifndef SSHGUARD_LOG_H
#define SSHGUARD_LOG_H

#include <syslog.h>

#define SLOG_SYSLOG     5
#define SLOG_STDERRR    10

/**
 * Initialize the logging system.
 *
 * This function must be called before any call to sshguard_log() is issued.
 * If debugging mode is wanted, the respective argument must be set to
 * non-zero.
 *
 * @param debugmode     0 if debugging disabled; non-0 otherwise
 * @return              0 if successful, non-0 otherwise
 */
int sshguard_log_init(int debugmode);


/**
 * Issue a log message.
 *
 * A log message is reported with the implemented subsystem. Depending on the
 * level of importance specified (prio), the message might be discarded if
 * irrelevant. The log message can be composed with standard printf() format
 * (fmt).
 *
 * If debugging is enabled, the message is printed to standard error.
 *
 * @return 0 iff successful
 */
int sshguard_log(int prio, char *fmt, ...);


/**
 * Finalize the logging system.
 *
 * This function is expected to be call when the logging system is not needed
 * anymore. No calls to sshguard_log() are expected after this.
 */
int sshguard_log_fin();

#endif

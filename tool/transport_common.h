/* Copyright (c) 2014, Google Inc.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE. */

#ifndef OPENSSL_HEADER_TOOL_TRANSPORT_COMMON_H
#define OPENSSL_HEADER_TOOL_TRANSPORT_COMMON_H

#include <openssl/ssl.h>
#include <string.h>
#define false 0
#define true 1

// InitSocketLibrary calls the Windows socket init functions, if needed.
int InitSocketLibrary();

// Connect sets |*out_sock| to be a socket connected to the destination given
// in |hostname_and_port|, which should be of the form "www.example.com:123".
// It returns true on success and false otherwise.
//We need to go back and provide support for this connect if we choose not to
//change the origional client (when we add it back in)
//bool Connect(int *out_sock, const std::string &hostname_and_port);

#ifdef CLIVER
int Connect(int *out_sock, char* hostname_and_port);
#endif
int PrintConnectionInfo(const SSL *ssl);

int SocketSetNonBlocking(int sock, int is_non_blocking);

int PrintErrorCallback(const char *str, size_t len, void *ctx);

int TransferData(SSL *ssl, int sock);


#endif  /* !OPENSSL_HEADER_TOOL_TRANSPORT_COMMON_H */

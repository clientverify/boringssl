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

#include <string.h>
#include <libgen.h>
#include <assert.h>

#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

int Client(int argc, char **argv);
char *tool_name = "client";
char *my_name = "bssl";

static void usage(const char *name) {
  printf("Usage: %s COMMAND\n", name);
  printf("\n");
  printf("Available commands:\n");
  printf("    %s\n", tool_name);
}

int main(int argc, char **argv) {
  CRYPTO_library_init();
  int starting_arg = 1;

  assert(strcmp(basename(argv[0]), my_name) == 0);
  starting_arg++;
  if (argc > 1) {
    if (strcmp(argv[1], tool_name) != 0) {
      usage(argv[0]);
      return 1;
    }
  } else {
    usage(argv[0]);
    return 1;
  }

 return !Client(argc-starting_arg, argv+starting_arg);
}

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

#include <openssl/base.h>

#include <stdio.h>

#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>

#include "../crypto/test/scoped_types.h"
#include "../ssl/test/scoped_types.h"
#include "internal.h"
#include "transport_common.h"


#ifdef CLIVER
#include <openssl/KTest.h>
static const char *arg_ktest_filename = NULL;
static enum kTestMode arg_ktest_mode = KTEST_NONE;
#endif

static const struct argument kArguments[] = {
    {
     "-connect", kRequiredArgument,
     "The hostname and port of the server to connect to, e.g. foo.com:443",
    },
    {
     "-cipher", kOptionalArgument,
     "An OpenSSL-style cipher suite string that configures the offered ciphers",
    },
#ifndef CLIVER
    {
     "-max-version", kOptionalArgument,
     "The maximum acceptable protocol version",
    },
    {
     "-min-version", kOptionalArgument,
     "The minimum acceptable protocol version",
    },
#endif
    {
     "-server-name", kOptionalArgument,
     "The server name to advertise",
    },
#ifndef CLIVER
    {
     "-select-next-proto", kOptionalArgument,
     "An NPN protocol to select if the server supports NPN",
    },
#endif
    {
     "-alpn-protos", kOptionalArgument,
     "A comma-separated list of ALPN protocols to advertise",
    },
#ifndef CLIVER
    {
     "-fallback-scsv", kBooleanArgument,
     "Enable FALLBACK_SCSV",
    },
#endif
    {
     "-ocsp-stapling", kBooleanArgument,
     "Advertise support for OCSP stabling",
    },
    {
     "-signed-certificate-timestamps", kBooleanArgument,
     "Advertise support for signed certificate timestamps",
    },
    {
     "-channel-id-key", kOptionalArgument,
     "The key to use for signing a channel ID",
    },
#ifndef CLIVER
    {
     "-false-start", kBooleanArgument,
     "Enable False Start",
    },
    { "-session-in", kOptionalArgument,
      "A file containing a session to resume.",
    },
    { "-session-out", kOptionalArgument,
      "A file to write the negotiated session to.",
    },
#endif
#ifdef CLIVER
    { "-record" , kOptionalArgument,
      "File to record packets and other inputs.",
    },
    { "-playback" , kOptionalArgument,
      "Playback client using inputs KTest file.",
    },
#endif
    {
      "-key", kOptionalArgument,
      "Private-key file to use (default is no client certificate)",
    },
    {
     "", kOptionalArgument, "",
    },
};

static ScopedEVP_PKEY LoadPrivateKey(char* file) {
  ScopedBIO bio(BIO_new(BIO_s_file()));
  if (!bio || !BIO_read_filename(bio.get(), file)) {
    return nullptr;
  }
  ScopedEVP_PKEY pkey(PEM_read_bio_PrivateKey(bio.get(), nullptr, nullptr,
                                              nullptr));
  return pkey;
}

#ifndef CLIVER
static bool VersionFromString(uint16_t *out_version,
                              const std::string& version) {
  if (version == "ssl3") {
    *out_version = SSL3_VERSION;
    return true;
  } else if (version == "tls1" || version == "tls1.0") {
    *out_version = TLS1_VERSION;
    return true;
  } else if (version == "tls1.1") {
    *out_version = TLS1_1_VERSION;
    return true;
  } else if (version == "tls1.2") {
    *out_version = TLS1_2_VERSION;
    return true;
  }
  return false;
}

static int NextProtoSelectCallback(SSL* ssl, uint8_t** out, uint8_t* outlen,
                                   const uint8_t* in, unsigned inlen, void* arg) {
  *out = reinterpret_cast<uint8_t *>(arg);
  *outlen = strlen(reinterpret_cast<const char *>(arg));
  return SSL_TLSEXT_ERR_OK;
}
#endif

static FILE *g_keylog_file = nullptr;

static void KeyLogCallback(const SSL *ssl, const char *line) {
  fprintf(g_keylog_file, "%s\n", line);
  fflush(g_keylog_file);
}
//#ifdef CLIVER
bool fail(){
    PrintUsage(kArguments);
    return false;
}

bool Client(int argc, char **argv) {

  //Variables
  char * cipher_string = NULL, *kfile = NULL, *connect_str = NULL,
    *server_name = NULL;
  std::vector<uint8_t> wire;
  bool ocsp_on = false, sig_cert_time = false;
  ScopedBIO bio;
  ScopedSSL ssl;
  int sock = -1, monotonically_decreasing;

  if(argc < 1) return fail();
while(argc > 0){
  monotonically_decreasing = argc;
#ifdef CLIVER
 if (strcmp(*argv,"-record") == 0){
    argv++;
    argc--;
    if(argc < 1) return fail();

    arg_ktest_filename = *argv;
    arg_ktest_mode = KTEST_RECORD;
    ktest_start(arg_ktest_filename, arg_ktest_mode);

    if(argc < 2) break;
    argv++;
    argc--;

  }
  else if(strcmp(*argv, "-playback") == 0){
    argv++;
    argc--;
    if(argc < 1) return fail();

    arg_ktest_filename = *argv;
    arg_ktest_mode = KTEST_PLAYBACK;
    ktest_start(arg_ktest_filename, arg_ktest_mode);

    if(argc < 2) break;
    argv++;
    argc--;
  }
#endif
  if (strcmp(*argv, "-cipher") == 0){
    argv++;
    argc--;
    if(argc < 1) return fail();
    cipher_string = *argv;

    if(argc < 2) break;
    argv++;
    argc--;

  }
  if (strcmp(*argv, "-alpn-protos") == 0) {
    argv++;
    argc--;
    if(argc < 1) return fail();

    char* alpn_protos = *argv;

    char* proto = strtok(alpn_protos, ",");
    int len;
    while (proto != NULL){
      len = strlen(proto);
      if (len > 255) {
        fprintf(stderr, "Invalid ALPN protocols: '%s'\n", alpn_protos);
        return false;
      }
      wire.push_back(static_cast<uint8_t>(len));
      wire.resize(wire.size() + len);
      memcpy(wire.data() + wire.size() - len, proto, len);

      proto = strtok(NULL, ",");
    }

    if(argc < 2) break;
    argv++;
    argc--;
  }



  if (strcmp(*argv, "-ocsp-stapling") == 0) {
    ocsp_on = true;

    if(argc < 2) break;
    argv++;
    argc--;
  }
  if (strcmp(*argv, "-signed-certificate-timestamps") == 0) {
    sig_cert_time = true;

    if(argc < 2) break;
    argv++;
    argc--;

  }
  if (strcmp(*argv, "-channel-id-key") == 0) {
    argv++;
    argc--;
    if(argc < 1) return fail();

    kfile = *argv;

    if(argc < 2) break;
    argv++;
    argc--;

  }


  if(strcmp(*argv, "-connect") == 0){
    argv++;
    argc--;
    if(argc < 1) return fail();

    connect_str = *argv;
    if(argc < 2) break;
    argv++;
    argc--;
  }

  if (strcmp(*argv, "-server-name") == 0) {
    argv++;
    argc--;
    if(argc < 1) return fail();

    server_name = *argv;

    if(argc < 2) break;
    argv++;
    argc--;
  }

  if(monotonically_decreasing == argc)  return fail();
}//XXX: end loop
  //Taken from top!
  if (!InitSocketLibrary()) {
    return false;
  }

  ScopedSSL_CTX ctx(SSL_CTX_new(SSLv23_client_method()));

  const char *keylog_file = getenv("SSLKEYLOGFILE");
  if (keylog_file) {
    g_keylog_file = fopen(keylog_file, "a");
    if (g_keylog_file == nullptr) {
      perror("fopen");
      return false;
    }
    SSL_CTX_set_keylog_callback(ctx.get(), KeyLogCallback);
  }

  if(cipher_string != NULL &&
    !SSL_CTX_set_cipher_list(ctx.get(), cipher_string)){
    fprintf(stderr, "Failed setting cipher list\n");
    return false;
  }

  if (wire.size() != 0 &&
    SSL_CTX_set_alpn_protos(ctx.get(), wire.data(), wire.size()) != 0) {
    return false;
  }

  if(ocsp_on) SSL_CTX_enable_ocsp_stapling(ctx.get());
  if(sig_cert_time) SSL_CTX_enable_signed_cert_timestamps(ctx.get());
  if(kfile != NULL){
    ScopedEVP_PKEY pkey = LoadPrivateKey(kfile);
    if (!pkey || !SSL_CTX_set1_tls_channel_id(ctx.get(), pkey.get())) {
      return false;
    }
  }

  if(connect_str != NULL) {
    if (!Connect(&sock, connect_str)) {
        return false;
    }
    bio = ScopedBIO(BIO_new_socket(sock, BIO_CLOSE));
    ssl = ScopedSSL(SSL_new(ctx.get()));
  } else return fail();

  if(server_name != NULL) {
    SSL_set_tlsext_host_name(ssl.get(), *argv);
  }

  SSL_set_bio(ssl.get(), bio.get(), bio.get());
  bio.release();

  printf("HAPPY TUESDAY: calling SSL_connect\n");
  int ret = SSL_connect(ssl.get());
  printf("HAPPY TUESDAY: completed SSL_connect\n");
  if (ret != 1) {
    int ssl_err = SSL_get_error(ssl.get(), ret);
    fprintf(stderr, "Error while connecting: %d\n", ssl_err);
    ERR_print_errors_cb(PrintErrorCallback, stderr);
    return false;
  }

  fprintf(stderr, "Connected.\n");
  PrintConnectionInfo(ssl.get());
  bool ok = TransferData(ssl.get(), sock);

#ifdef CLIVER
  ktest_finish();
#endif
  return ok;
}

//#endif

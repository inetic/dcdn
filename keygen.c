#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include "sodium.h"

unsigned char pk[crypto_sign_PUBLICKEYBYTES];
unsigned char sk[crypto_sign_SECRETKEYBYTES];

int main() {
    crypto_sign_keypair(pk, sk);

    int sk_f = open("injector_sk", O_CREAT | O_EXCL | O_WRONLY, 0644);

    if (sk_f == -1) {
        fprintf(stderr, "Could not create the file injector_sk: %s\n", strerror(errno));
        exit(1);
    }

    int pk_f = open("injector_pk", O_CREAT | O_EXCL | O_WRONLY, 0644);

    if (pk_f == -1) {
        fprintf(stderr, "Could not create the file injector_pk: %s\n", strerror(errno));
        close(sk_f);
        exit(1);
    }

    write(sk_f, sk, sizeof(sk));
    write(pk_f, pk, sizeof(pk));

    close(sk_f);
    close(pk_f);
}

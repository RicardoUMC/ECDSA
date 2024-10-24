#include "../ecop/EC.h"
#include <stdio.h>
#include <string.h>
#include <openssl/rand.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/sha.h>

void configure_public_params(mpz_t p, mpz_t a, mpz_t b, mpz_t q, ec_point *G);
void generate_key_pair(mpz_t p, mpz_t a, mpz_t b, mpz_t q, ec_point *G, char *priv_filename, char *pub_filename);
void ecdsa_signature(mpz_t d, mpz_t m, mpz_t p, mpz_t a, mpz_t b, mpz_t q, ec_point *G, char *filename);
bool ecdsa_verification(mpz_t m, char *pubkey_file, char *signature_file);
void sha256_of_file(const char *filename, mpz_t m);

char *base64_encode(const char *input);
char *base64_decode(const char *input);

int main(void) {
    mpz_t p, a, b, q, d, m;
    ec_point G;
    int option;
    bool keys_generated = false, signature_generated = false;

    mpz_inits(p, a, b, q, d, m, G.x, G.y, NULL);

    while (1) {
        printf("\nMenu:\n");
        printf("1. Generate Keys\n");
        printf("2. Sign File\n");
        printf("3. Verify Signature\n");
        printf("4. Exit\n");
        printf("Select an option: ");
        scanf("%d", &option);

        switch (option) {
            case 1:
                configure_public_params(p, a, b, q, &G);
                generate_key_pair(p, a, b, q, &G, "ecdsa_private_key.pem", "ecdsa_public_key.pem");
                keys_generated = true;
                break;
            case 2:
                if (!keys_generated) {
                    printf("Please generate keys first.\n");
                    break;
                }
                printf("Enter the private key d: ");
                mpz_inp_str(d, stdin, 10);

                char file_to_sign[256];
                printf("Enter the file path to sign: ");
                scanf("%s", file_to_sign);

                sha256_of_file(file_to_sign, m);

                ecdsa_signature(d, m, p, a, b, q, &G, "ecdsa_signature.txt");
                signature_generated = true;
                break;
            case 3:
                if (!signature_generated) {
                    printf("Please sign a message first.\n");
                    break;
                }

                char file_to_verify[256];
                printf("Enter the file path to verify: ");
                scanf("%s", file_to_verify);

                sha256_of_file(file_to_verify, m);

                ecdsa_verification(m, "ecdsa_public_key.pem", "ecdsa_signature.txt") ?
                    printf("The signature is valid.\n") :
                    printf("The signature is not valid.\n");

                break;
            case 4:
                printf("Exiting program.\n");
                mpz_clears(p, a, b, q, d, m, G.x, G.y, NULL);
                return 0;
            default:
                printf("Invalid option. Please select again.\n");
                break;
        }
    }
}

void configure_public_params(mpz_t p, mpz_t a, mpz_t b, mpz_t q, ec_point *G) {
    printf("Enter a prime number p: ");
    mpz_inp_str(p, stdin, 10);

    printf("Enter coefficient a for the elliptic curve: ");
    mpz_inp_str(a, stdin, 10);

    printf("Enter coefficient b for the elliptic curve: ");
    mpz_inp_str(b, stdin, 10);

    printf("Enter the order q of the generator point G: ");
    mpz_inp_str(q, stdin, 10);

    printf("Enter the generator point G coordinates (xG:yG:1):\n");
    printf("xG = ");
    mpz_inp_str(G->x, stdin, 10);
    printf("yG = ");
    mpz_inp_str(G->y, stdin, 10);
    G->z = 1;
}

void generate_key_pair(mpz_t p, mpz_t a, mpz_t b, mpz_t q, ec_point *G, char *priv_filename, char *pub_filename) {
    mpz_t d;
    ec_point B;

    mpz_inits(d, B.x, B.y, NULL);

    uint8_t buffer[32];
    if (RAND_bytes(buffer, sizeof(buffer)) != 1) {
        perror("Error generating secure random bytes");
        mpz_clears(d, B.x, B.y, NULL);
        return;
    }

    mpz_import(d, sizeof(buffer), 1, sizeof(buffer[0]), 0, 0, buffer);
    mpz_mod(d, d, q);

    B = point_multiplication(a, b, p, G, d);

    FILE *priv_file = fopen(priv_filename, "w");
    if (priv_file == NULL) {
        perror("Error opening private key file");
        mpz_clears(d, B.x, B.y, NULL);
        return;
    }
    char *encoded_d = base64_encode(mpz_get_str(NULL, 10, d));
    fprintf(priv_file, "-----BEGIN ECDSA PRIVATE KEY-----\n%s\n-----END ECDSA PRIVATE KEY-----\n", encoded_d);
    fclose(priv_file);
    free(encoded_d);

    FILE *pub_file = fopen(pub_filename, "w");
    if (pub_file == NULL) {
        perror("Error opening public key file");
        mpz_clears(d, B.x, B.y, NULL);
        return;
    }
    char *encoded_Bx = base64_encode(mpz_get_str(NULL, 10, B.x));
    char *encoded_By = base64_encode(mpz_get_str(NULL, 10, B.y));
    fprintf(pub_file, "-----BEGIN ECDSA PUBLIC KEY-----\n%s\n%s\n-----END ECDSA PUBLIC KEY-----\n", encoded_Bx, encoded_By);
    fclose(pub_file);
    free(encoded_Bx);
    free(encoded_By);

    gmp_printf("Private key d: %Zd\n", d);
    gmp_printf("Public key B: (%Zd:%Zd:%d)\n", B.x, B.y, B.z);

    mpz_clears(d, B.x, B.y, NULL);
}

void sha256_of_file(const char *filename, mpz_t m) {
    FILE *file = fopen(filename, "rb");
    if (file == NULL) {
        perror("Error opening file");
        return;
    }

    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    unsigned char buffer[1024];
    size_t bytesRead;

    while ((bytesRead = fread(buffer, 1, sizeof(buffer), file))) {
        SHA256_Update(&sha256, buffer, bytesRead);
    }

    fclose(file);

    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_Final(hash, &sha256);

    mpz_import(m, SHA256_DIGEST_LENGTH, 1, 1, 0, 0, hash);
}

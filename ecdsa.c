#include "../ecop/EC.h"
#include <stdio.h>
#include <string.h>
#include <openssl/rand.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/sha.h>

void configure_public_params(mpz_t p, mpz_t a, mpz_t b, mpz_t q, ec_point *G);
void generate_key_pair(mpz_t p, mpz_t a, mpz_t b, mpz_t q, ec_point *G, char *priv_filename, char *pub_filename);
void ecdsa_signature(mpz_t m, mpz_t p, mpz_t a, mpz_t b, mpz_t q, ec_point *G, char *filename);
bool ecdsa_verification(mpz_t m, char *pubkey_file, char *signature_file);
void sha256_of_file(const char *filename, mpz_t m);

char *base64_encode(const char *input);
bool base64_decode_to_mpz(const char *input, mpz_t result);

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
                /*if (!keys_generated) {
                    printf("Please generate keys first.\n");
                    break;
                }*/

                char file_to_sign[256];
                printf("Enter the file path to sign: ");
                scanf("%s", file_to_sign);

                sha256_of_file(file_to_sign, m);

                ecdsa_signature(m, p, a, b, q, &G, "ecdsa_signature.txt");
                signature_generated = true;
                break;
            case 3:
                /*if (!signature_generated) {
                    printf("Please sign a message first.\n");
                    break;
                }*/

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
    char *encoded_p = base64_encode(mpz_get_str(NULL, 10, p));
    char *encoded_a = base64_encode(mpz_get_str(NULL, 10, a));
    char *encoded_b = base64_encode(mpz_get_str(NULL, 10, b));
    char *encoded_q = base64_encode(mpz_get_str(NULL, 10, q));
    char *encoded_Gx = base64_encode(mpz_get_str(NULL, 10, G->x));
    char *encoded_Gy = base64_encode(mpz_get_str(NULL, 10, G->y));
    char *encoded_Bx = base64_encode(mpz_get_str(NULL, 10, B.x));
    char *encoded_By = base64_encode(mpz_get_str(NULL, 10, B.y));
    fprintf(pub_file, "-----BEGIN ECDSA PUBLIC KEY-----\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n-----END ECDSA PUBLIC KEY-----\n", encoded_p, encoded_a, encoded_b, encoded_q, encoded_Gx, encoded_Gy, encoded_Bx, encoded_By);
    fclose(pub_file);
    free(encoded_p);
    free(encoded_a);
    free(encoded_b);
    free(encoded_q);
    free(encoded_Gx);
    free(encoded_Gy);
    free(encoded_Bx);
    free(encoded_By);

    gmp_printf("Private key d: %Zd\n", d);
    gmp_printf("Public key B: (%Zd:%Zd:%d)\n", B.x, B.y, B.z);

    mpz_clears(d, B.x, B.y, NULL);
}

void ecdsa_signature(mpz_t m, mpz_t p, mpz_t a, mpz_t b, mpz_t q, ec_point *G, char *filename) {
    mpz_t d, r, s, k, k_inv, temp;
    ec_point R;
    char buffer[64]; 

    mpz_inits(d, r, s, k, k_inv, R.x, R.y, temp, NULL);

    FILE *file = fopen("ecdsa_private_key.pem", "r");
    if (file == NULL) {
        perror("Error opening private key file");
        mpz_clears(d, r, s, k, k_inv, R.x, R.y, temp, NULL);
        return;
    }

    char encoded_d[64]; 
    fgets(buffer, sizeof(buffer), file);
    fgets(encoded_d, sizeof(encoded_d), file);
    fgets(buffer, sizeof(buffer), file);
    fclose(file);

    encoded_d[strlen(encoded_d)-1] = '\0';

    if (!base64_decode_to_mpz(encoded_d, d)) {
        perror("Error decoding base64 and importing values\n");
    }

    do {
        do {
            uint8_t buffer[32];
            if (RAND_bytes(buffer, sizeof(buffer)) != 1) {
                perror("Error generating secure random bytes");
                mpz_clears(d, r, s, k, k_inv, R.x, R.y, temp, NULL);
                return;
            }

            mpz_import(k, sizeof(buffer), 1, sizeof(buffer[0]), 0, 0, buffer);
            mpz_mod(k, k, q);
        } while (mpz_cmp_ui(k, 1) < 0);

        R = point_multiplication(a, b, p, G, k);

        mpz_set(r, R.x);

        if (mpz_invert(k_inv, k, q) == 0) {
            perror("K has no modular inverse");
            mpz_clears(r, s, k, k_inv, R.x, R.y, temp, NULL);
            return;
        }

        mpz_mul(temp, d, r);
        mpz_add(temp, temp, m);
        mpz_mod(temp, temp, q);

        mpz_mul(s, temp, k_inv);
        mpz_mod(s, s, q);
    } while (mpz_cmp_ui(s, 0) <= 0);

    file = fopen(filename, "w");
    if (file == NULL) {
        perror("Error opening signature file");
        mpz_clears(d, r, s, k, k_inv, R.x, R.y, temp, NULL);
        return;
    }

    char *encoded_r = base64_encode(mpz_get_str(NULL, 10, r));
    char *encoded_s = base64_encode(mpz_get_str(NULL, 10, s));
    fprintf(file, "%s\n%s\n", encoded_r, encoded_s);
    fclose(file);
    free(encoded_r);
    free(encoded_s);

    gmp_printf("Signature: (r, s) = (%Zd, %Zd)\n", r, s);

    mpz_clears(d, r, s, k, k_inv, R.x, R.y, temp, NULL);
}

bool ecdsa_verification(mpz_t m, char *pubkey_file, char *signature_file) {
    printf("Verifying\n");
    mpz_t w, aux_1, aux_2, p, a, b, q, r, s;
    ec_point G, B, P, P_temp_1, P_temp_2;

    mpz_inits(w, aux_1, aux_2, p, a, b, q, r, s, G.x, G.y, B.x, B.y, P.x, P.y, P_temp_1.x, P_temp_1.y, P_temp_2.x, P_temp_2.y, NULL);

    FILE *file = fopen(pubkey_file, "r");
    if (file == NULL) {
        perror("Error opening public key file");
        mpz_clears(w, aux_1, aux_2, p, a, b, q, r, s, G.x, G.y, B.x, B.y, P.x, P.y, P_temp_1.x, P_temp_1.y, P_temp_2.x, P_temp_2.y, NULL);
        return false;
    }

    char encoded_p[64], encoded_a[64], encoded_b[64], encoded_q[64], encoded_Gx[64], encoded_Gy[64], encoded_Bx[64], encoded_By[64], buffer[64];
    fgets(buffer, sizeof(buffer), file);
    fgets(encoded_p, sizeof(encoded_p), file);
    fgets(encoded_a, sizeof(encoded_a), file);
    fgets(encoded_b, sizeof(encoded_b), file);
    fgets(encoded_q, sizeof(encoded_q), file);
    fgets(encoded_Gx, sizeof(encoded_Gx), file);
    fgets(encoded_Gy, sizeof(encoded_Gy), file);
    fgets(encoded_Bx, sizeof(encoded_Bx), file);
    fgets(encoded_By, sizeof(encoded_By), file);
    fgets(buffer, sizeof(buffer), file);
    fclose(file);

    encoded_p[strlen(encoded_p)-1] = '\0';
    encoded_a[strlen(encoded_a)-1] = '\0';
    encoded_b[strlen(encoded_b)-1] = '\0';
    encoded_q[strlen(encoded_q)-1] = '\0';
    encoded_Gx[strlen(encoded_Gx)-1] = '\0';
    encoded_Gy[strlen(encoded_Gy)-1] = '\0';
    encoded_Bx[strlen(encoded_Bx)-1] = '\0';
    encoded_By[strlen(encoded_By)-1] = '\0';

    if (!base64_decode_to_mpz(encoded_p, p) ||
            !base64_decode_to_mpz(encoded_a, a) ||
            !base64_decode_to_mpz(encoded_b, b) ||
            !base64_decode_to_mpz(encoded_q, q) ||
            !base64_decode_to_mpz(encoded_Gx, G.x) ||
            !base64_decode_to_mpz(encoded_Gy, G.y) ||
            !base64_decode_to_mpz(encoded_Bx, B.x) ||
            !base64_decode_to_mpz(encoded_By, B.y)) {
        perror("Error decoding base64 and importing values\n");
    }

    mpz_mod(G.x, G.x, q);
    mpz_mod(G.y, G.y, q);
    G.z = 1;
    mpz_mod(B.x, B.x, q);
    mpz_mod(B.y, B.y, q);
    B.z = 1;

    file = fopen(signature_file, "r");
    if (file == NULL) {
        perror("Error opening signature file");
        mpz_clears(w, aux_1, aux_2, p, a, b, q, r, s, G.x, G.y, B.x, B.y, P.x, P.y, P_temp_1.x, P_temp_1.y, P_temp_2.x, P_temp_2.y, NULL);
        return false;
    }

    char encoded_r[64], encoded_s[64];
    fgets(encoded_r, sizeof(encoded_r), file);
    fgets(encoded_s, sizeof(encoded_s), file);
    fclose(file);

    encoded_r[strlen(encoded_r)-1] = '\0';
    encoded_s[strlen(encoded_s)-1] = '\0';

    if (!base64_decode_to_mpz(encoded_r, r) ||
            !base64_decode_to_mpz(encoded_s, s)) {
        perror("Error decoding base64 and importing values\n");
    }

    mpz_mod(r, r, q);
    mpz_mod(s, s, q);

    if (mpz_invert(w, s, q) == 0) {
        perror("S has no modular inverse");
        mpz_clears(w, aux_1, aux_2, p, a, b, q, r, s, G.x, G.y, B.x, B.y, P.x, P.y, P_temp_1.x, P_temp_1.y, P_temp_2.x, P_temp_2.y, NULL);
        return false;
    }

    mpz_mul(aux_1, w, m);
    mpz_mod(aux_1, aux_1, q);

    mpz_mul(aux_2, w, r);
    mpz_mod(aux_2, aux_2, q);

    P_temp_1 = point_multiplication(a, b, p, &G, aux_1);
    P_temp_2 = point_multiplication(a, b, p, &B, aux_2);
    P = point_addition(a, b, p, &P_temp_1, &P_temp_2);

    bool is_valid = (mpz_cmp(P.x, r) == 0);

    mpz_clears(w, aux_1, aux_2, p, a, b, q, r, s, G.x, G.y, B.x, B.y, P.x, P.y, P_temp_1.x, P_temp_1.y, P_temp_2.x, P_temp_2.y, NULL);

    return is_valid;
}

char *base64_encode(const char *input) {
    BIO *bio, *b64;
    BUF_MEM *bufferPtr;

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);

    BIO_write(bio, input, strlen(input));
    BIO_flush(bio);

    BIO_get_mem_ptr(bio, &bufferPtr);
    BIO_set_close(bio, BIO_NOCLOSE);
    BIO_free_all(bio);

    char *encoded = (char *)malloc(bufferPtr->length + 1);
    memcpy(encoded, bufferPtr->data, bufferPtr->length);
    encoded[bufferPtr->length] = '\0';

    return encoded;
}

bool base64_decode_to_mpz(const char *input, mpz_t result) {
    BIO *bio, *b64;
    int length = strlen(input);
    int max_decoded_size = (length * 3) / 4 + 1;  // Añadimos 1 para posibles caracteres de relleno

    uint8_t *decoded = (uint8_t *)malloc(max_decoded_size);
    if (decoded == NULL) {
        return false;
    }

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new_mem_buf(input, length);
    bio = BIO_push(b64, bio);
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);

    int actual_decoded_length = BIO_read(bio, decoded, length);
    if (actual_decoded_length <= 0) {
        BIO_free_all(bio);
        free(decoded);
        return false;
    }

    decoded[actual_decoded_length] = '\0';
    mpz_set_str(result, decoded, 10);

    BIO_free_all(bio);
    free(decoded);
    return true;
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

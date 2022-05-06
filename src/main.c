#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <openssl/evp.h>
#include <openssl/aes.h>

// 32*8 = 256bit

typedef unsigned char byte;

void print_hex_array(byte key[], int length) {
  printf("{ ");
  for (int i=0; i<length; i++)
    printf("0x%x ", key[i]);
  printf("}\n");
}

int aes_init(byte *key_data, int key_data_len, EVP_CIPHER_CTX *e_ctx, EVP_CIPHER_CTX *d_ctx) {
  int i, nrounds = 5;
  byte key[32], iv[32];
  
  /*
   * Gen key & IV for AES 256 CBC mode. A SHA1 digest is used to hash the supplied key material.
   * nrounds is the number of times the we hash the material. More rounds are more secure but
   * slower.
   */
  i = EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha1(), NULL, key_data, key_data_len, nrounds, key, iv);
  if (i != 32) {
    fprintf(stderr, "! Key size is %d bits - should be 256 bits\n", i);
    return -1;
  }

  EVP_EncryptInit_ex(e_ctx, EVP_aes_256_cbc(), NULL, key, iv);
  EVP_DecryptInit_ex(d_ctx, EVP_aes_256_cbc(), NULL, key, iv);

  return 0;
}

/*
 * Encrypt *len bytes of data
 * All data going in & out is considered binary (byte[]).
 */
byte* aes_encrypt(EVP_CIPHER_CTX *e, byte *plaintext, int *len) {
  /* Max ciphertext len for a n bytes of plaintext is n + AES_BLOCK_SIZE -1 bytes. */
  int c_len = *len + AES_BLOCK_SIZE, f_len = 0;
  byte *ciphertext = malloc(c_len);

  /* Allows reusing of 'e' for multiple encryption cycles. */
  EVP_EncryptInit_ex(e, NULL, NULL, NULL, NULL);

  /* Update ciphertext, c_len is filled with the length of ciphertext generated,
   * len is the size of plaintext in bytes. */
  EVP_EncryptUpdate(e, ciphertext, &c_len, plaintext, *len);

  /* Update ciphertext with the final remaining bytes. */
  EVP_EncryptFinal_ex(e, ciphertext+c_len, &f_len);

  *len = c_len + f_len;
  return ciphertext;
}

/*
 * Decrypt *len bytes of ciphertext
 */
byte *aes_decrypt(EVP_CIPHER_CTX *e, byte *ciphertext, int *len)
{
  /* Plaintext will always be equal to or lesser than length of ciphertext */
  int p_len = *len, f_len = 0;
  byte *plaintext = malloc(p_len);
  
  EVP_DecryptInit_ex(e, NULL, NULL, NULL, NULL);
  EVP_DecryptUpdate(e, plaintext, &p_len, ciphertext, *len);
  EVP_DecryptFinal_ex(e, plaintext+p_len, &f_len);

  *len = p_len + f_len;
  return plaintext;
}

typedef struct {
  byte *fbytes;
  size_t length;
} file_wsize;

int generate_key(char* filename, byte key[32]) {
  FILE* file = fopen(filename, "wb");
  if (!file) {
    return 1;
  }

  for (int i=0; i<32; i++) {
    key[i] = rand() % (255+1);
  }

  fwrite(key, 1, 32, file);
  return 0;
}

int read_key(char* filename, byte key[32]) {
  FILE* file = fopen(filename, "rb");
  if (!file) {
    return 1;
  }

  struct stat sb;
  if (stat(filename, &sb) == -1) {
    fprintf(stderr, "! `stat` error\n");
    return -1;
  }

  if (sb.st_size != 32) {
    fprintf(stderr, "! Key file `%s` invalid\n", filename);
    return -1;
  }

  fread(key, 1, 32, file);
  return 0;
}

file_wsize get_file_contents(char* filename) {
  FILE* file = fopen(filename, "rb");
  struct stat sb;
  if (stat(filename, &sb) == -1) {
    fprintf(stderr, "! `stat` error\n");
    return (file_wsize) { NULL, 0 };
  }

  byte* fbytes = malloc(sb.st_size);
  fread(fbytes, sb.st_size, 1, file);
  fclose(file);
  return (file_wsize) {
    fbytes, sb.st_size
  };
}

int write_to_file(char* filename, byte* fbytes, int len) {
  FILE* file = fopen(filename, "wb");
  if (!file) {
    fprintf(stderr, "! Error opening file `%s`\n", filename);
    return -1;
  }

  fwrite(fbytes, 1, len, file);
  fclose(file);

  return 0;
}

int main(int argc, char* argv[]) {
  if (argc < 3+1) {
    fprintf(stderr, "! Too few arguemnts\nUsage: fenc <input filename> <output filename> <[encrypt, decrypt]> <key filename?>\n");
    return -1;
  }
  char* in_filename = argv[1];
  char* out_filename = argv[2];
  char* operation = argv[3];
  char* key_filename;
  if (argc == 5) key_filename = argv[4];

  if (strcmp(operation, "encrypt") != 0 && strcmp(operation, "decrypt") != 0) {
    fprintf(stderr, "! Operation must be either `encrypt` or `decrypt`\n");
    return -1;
  }

  EVP_CIPHER_CTX *en = EVP_CIPHER_CTX_new(),
                 *de = EVP_CIPHER_CTX_new();

  // key stuff
  byte key_data[32];
  int key_data_len = 32;
  if (read_key(key_filename, key_data) > 0) {
    printf("Key not found, generating `key.key`...\n");
    generate_key("key.key", key_data);
  };

  // initialize AES
  if (aes_init(key_data, key_data_len, en, de)) {
    fprintf(stderr, "! Couldn't initialize AES cipher\n");
    return -1;
  }

  // encrypt operation
  if (strcmp(operation, "encrypt") == 0) {
    file_wsize fdata_en = get_file_contents(in_filename);
    int len_en = fdata_en.length;

    byte *encrypted = aes_encrypt(en, fdata_en.fbytes, &len_en);
    write_to_file(out_filename, encrypted, len_en);

    free(fdata_en.fbytes);
    free(encrypted);
  // decrypt operation
  } else if (strcmp(operation, "decrypt") == 0) {
    file_wsize fdata_de = get_file_contents(in_filename);
    int len_de = fdata_de.length;

    byte *decrypted = aes_decrypt(de, fdata_de.fbytes, &len_de);
    write_to_file(out_filename, decrypted, len_de);

    free(fdata_de.fbytes);
    free(decrypted);
  }

  return 0;
}

#ifndef FT_OTP
#define FT_OTP


#include <openssl/hmac.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <string.h>
#include <stdint.h>
#include <math.h>
#include <assert.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <zlib.h>



#define SHA1_DIGEST_LENGTH 20
#define DEFAULT_TIME_TO_STEP 30
#define DEFAULT_TO 0
#define MAX_OTP_DIGITS 8

// key manageement definnitions
#define KEY_SIZE 32 // 256 bits
#define SALT_SIZE 16
#define IV_SIZE 16
#define KEY_FILE_MODE (S_IRUSR | S_IWUSR)
#define HMAC_SIZE 32


//-------
//|| ERROR CODE STRUCTS
//||
//-------
typedef enum {
	ERROR_NONE = 0,
	ERROR_INVALID_INPUT,
	ERROR_INVALID_DIGITS,
	ERROR_HMAC_COMPUTATION_FAILED,
	ERROR_MEMORY_ALLOCATION,
	ERROR_TIME_FAILURE,
	ERROR_HOTP_GENERATION_FAILED,
	ERROR_IMPL_ERROR,
	ERROR_FUNC_ERROR,
	ERROR_BUFFER_OVERFLOW,
	//Key manmagemennt enccyrption eerrors
	ERROR_RANDOM_GENERATION,
	ERROR_KEY_DERIVATION,
	ERROR_CIPHER_CONTEXT,
	ERROR_ENCRYPT_ERROR,
	ERROR_INVALID_KEY_SIZE,
	ERROR_LOW_KEY_ENTROPY,
	// key management decryption
	ERROR_INVALID_DATA_SIZE,
	ERROR_DECRYPT_INIT,
	ERROR_DECRYPT_UPDATE,
	ERROR_DECRYPT_FINAL,
	ERROR_INVALID_MAGIC_BYTES,
	ERROR_FILE_OPEN,
	ERROR_FILE_WRITE,
	ERROR_FILE_SYNC,
	ERROR_FILE_READ,
	ERROR_FILE_STAT,
	ERROR_BUFFER_TOO_SMALL,
	ERROR_INTEGRITY_CHECK

} ErrorCode;
//-------
//|| ERROR DETAILA STRUCTS
//||
//-------
typedef struct {
	ErrorCode error_code;
	char message[256];
} ErrorDetails;

// HMAC function
int compute_hmac_sha1(const unsigned char *key, size_t key_len,
					const unsigned char *data, size_t data_len,
					unsigned char *digest, unsigned int *digest_len);

// hotp functions
int generate_hotp(const unsigned char *key, size_t key_len, uint64_t counter, int digits, char *otp, ErrorDetails *err);

// totp functions
uint64_t get_time_step(time_t time, unsigned int time_step_seconds, time_t t0);
int constant_time_compare(const char *a, const char *b, size_t length);
int generate_totp(const unsigned char *key, size_t key_len, int digits, unsigned int time_step_seconds, \
					time_t t0, char *otp, ErrorDetails *err);

// Key management functions
int validate_key(const unsigned char *key, size_t key_size, ErrorDetails *err);
int generate_key(unsigned char *key, size_t key_size, ErrorDetails *err);
int encrypt_key(const unsigned char *key, size_t key_size, const char *password, size_t password_len,
				unsigned char *encrypted_data, size_t *encrypted_data_len, ErrorDetails *err);
int decrypt_key(const unsigned char *encrypted_data, size_t encrypted_data_len, 
				const char *password, size_t password_len, unsigned char *key,
				size_t *key_size, ErrorDetails *err);
int save_encrypted_key(const char *filename, const unsigned char *encrypted_data,
			size_t encrypted_dat_len, ErrorDetails *err);
int load_encrypted_key(const char *filename, unsigned char *encrypted_data, size_t *encrypted_data_len, ErrorDetails *err);

// memory functions
void* allocate_memory(size_t size, ErrorDetails *err);

// error functions
void set_error(ErrorDetails *err, ErrorCode code, const char *message);
void handle_error(ErrorDetails *err);

#endif




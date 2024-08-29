#include "../include/ft_otp.h"

uint64_t get_time_step(time_t time, unsigned int time_step_seconds, time_t t0) {
	// inital state
	// time: current time
	// time_step_seconds: time step size
	// t0: epoch start

	// transfoormaation: calculare number oof time steps since t0
	uint64_t steps = (time - t0) / time_step_seconds;

	// final state: time step coiunted as uint64

	return steps;

}

int generate_totp(const unsigned char *key, size_t key_len, int digits, unsigned int time_step_seconds, \
					time_t t0, char *otp, ErrorDetails *err) {
		// intial state:
		// key: seccreet keu for hmacc
		// key_len: length of the secret key
		// digits: desired length pf the otp
		// time_steepe to seconds: time step size
		//t0 : epoch start
		// otp: uninitializeed buffer for storing otp
		
		// transformation
		// validate inpit
		// get current time
		// calculate cutteeent time step
		// heneraate hotp using the time step as the counnter

		// valifatee input
		if (digits < 6 || digits > MAX_OTP_DIGITS) {
			set_error(err, ERROR_INVALID_INPUT, "Invalid digit count inside genratae totp");
			return -1;
		}

		// geet cuttent time
		time_t current_time = t0;
		uint64_t time_step;

		// If I ever need to use actual time
		// if (time(&current_time) == (time_t)(-1)) {
		// 	set_error(err, ERROR_TIME_FAILURE, "Failed to get current time. totp");
		// 	return -1;
		// }

		// calaccualte time step
		time_step = (current_time - 0) / time_step_seconds;
		// time_step = get_time_step(current_time, time_step_seconds, t0);

		// generate hotp using th etime step as the countet
		int result = generate_hotp(key, key_len, time_step, digits, otp, err);

		if (result != 0) {
			printf("Generate hotp failed inside generaate totp: %s\n", err->message);
			return -1;
		}

		// final state:
		// otp: string containinng rhw genrated totp
		return 0;
}

int verify_totp(const unsigned char *key, size_t key_len, const char *provided_otp, int digits, \
				unsigned int time_step_seconds, time_t t0, int window, ErrorDetails *err) {

		// initial state:
		// key: secret key for hmac
		// key len: length of secteet key
		// privided_hotp: OTP provided by user
		// digits: expected lenfth of otp
		//time_step_seconds: time step size
		// t0 : epoch start
		// window: nnumber of time steps to check beforw and after
		// err: uninitialied eerror details

		// transformationn
		// 1. validate input
		// 2. get current time step
		// 4. Gwenerate and compare OTPs for the time window 

		// Validte input
		if (digits < 6 || digits > MAX_OTP_DIGITS) {
			set_error(err, ERROR_INVALID_INPUT, "Invalid digit count inside verify otp");
			return -1;
		}
		// get current time step
		char calculated_otp[MAX_OTP_DIGITS + 1]; // +1 for null terminator
		time_t current_time;
		uint64_t time_step;

		if (time(&current_time) == (time_t)(-1)) {
			set_error(err, ERROR_IMPL_ERROR, "Error getting time stepp inside verify_otp");
			return -1;
		}

		time_step = get_time_step(current_time, time_step_seconds, t0);

		for (int i = -window; i <=window; i++) {
			if (generate_hotp(key, key_len, time_step + i , digits, calculated_otp, err) != 0) {
				printf("Generate hotp failed inside verify totp : %s", err->message);
				return -1;
			}
			if (constant_time_compare(calculated_otp, provided_otp, digits) == 0) {
				return 1; // OTP VALID
			}
		}

		// desired state:
		// OTP verified successfully or invlaid
		return 0;

}

int constant_time_compare(const char *a, const char *b, size_t length) {
	// initiaal state:
	// a, b: strinngs to compare
	// length numner of chaaracters to compare

	unsigned char result = 0;
	for (size_t i = 0; i < length ; i++) {
		result |= a[i] ^ b[i];
	}

	// final state: 0 if strings are equal, non-zero otherwise
	return result;
}

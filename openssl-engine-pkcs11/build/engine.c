#include <openssl/engine.h>

/**
 * These functions are defined as functions in 1.0.0 and as macros in 1.1.0, so invoke them from C.
 *
 * Also take the opportunity to memoize them in C rather than in Rust.
 */
int get_engine_ex_index() {
	static int result = -1;

	if (result == -1) {
		// TODO: dupf, freef
		result = ENGINE_get_ex_new_index(0, NULL, NULL, NULL, NULL);
	}

	return result;
}

void freef_ec_key_ex_data(void* parent, void* ptr, CRYPTO_EX_DATA* ad, int idx, long argl, void* argp);

int get_ec_key_ex_index() {
	static int result = -1;

	if (result == -1) {
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
		// TODO: dupf
		result = EC_KEY_get_ex_new_index(0, NULL, NULL, NULL, freef_ec_key_ex_data);
#else
		// TODO: dupf
		result = ECDSA_get_ex_new_index(0, NULL, NULL, NULL, freef_ec_key_ex_data);
#endif
	}

	return result;
}

void freef_rsa_ex_data(void* parent, void* ptr, CRYPTO_EX_DATA* ad, int idx, long argl, void* argp);

int get_rsa_ex_index() {
	static int result = -1;

	if (result == -1) {
		// TODO: dupf
		result = RSA_get_ex_new_index(0, NULL, NULL, NULL, freef_rsa_ex_data);
	}

	return result;
}

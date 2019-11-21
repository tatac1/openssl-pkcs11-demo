#include <openssl/engine.h>

/**
 * The *_get_ex_new_index functions are defined as functions in 1.0.0 and as macros in 1.1.0,
 * so invoke them from C instead of creating complicated bindings.
 */

void freef_engine_ex_data(void* parent, void* ptr, CRYPTO_EX_DATA* ad, int idx, long argl, void* argp);

int get_engine_ex_index() {
	// TODO: dupf
	return ENGINE_get_ex_new_index(0, NULL, NULL, NULL, freef_engine_ex_data);
}

void freef_ec_key_ex_data(void* parent, void* ptr, CRYPTO_EX_DATA* ad, int idx, long argl, void* argp);

int get_ec_key_ex_index() {
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
	// TODO: dupf
	return EC_KEY_get_ex_new_index(0, NULL, NULL, NULL, freef_ec_key_ex_data);
#else
	// TODO: dupf
	return ECDSA_get_ex_new_index(0, NULL, NULL, NULL, freef_ec_key_ex_data);
#endif
}

void freef_rsa_ex_data(void* parent, void* ptr, CRYPTO_EX_DATA* ad, int idx, long argl, void* argp);

int get_rsa_ex_index() {
	// TODO: dupf
	return RSA_get_ex_new_index(0, NULL, NULL, NULL, freef_rsa_ex_data);
}

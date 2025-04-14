package com.neurallog.client.crypto;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

/**
 * Manages the key hierarchy for the NeuralLog client.
 *
 * The key hierarchy is as follows:
 * 1. Master Secret (derived from username:password)
 * 2. Key Encryption Key (KEK) (encrypted with Master Secret)
 * 3. API Key (derived from KEK + Tenant ID + Key ID)
 * 4. Log Encryption Key (derived from API Key + Tenant ID + Log Name)
 * 5. Log Search Key (derived from API Key + Tenant ID + Log Name)
 * 6. Log Name Key (derived from API Key + Tenant ID)
 */
public class KeyHierarchy {

    private static final String HMAC_ALGORITHM = "HmacSHA256";
    private static final String LOG_ENCRYPTION_KEY_CONTEXT = "log_encryption";
    private static final String LOG_SEARCH_KEY_CONTEXT = "log_search";
    private static final String LOG_NAME_KEY_CONTEXT = "log_name";
    private static final String API_KEY_CONTEXT = "api_key";
    private static final String KEK_CONTEXT = "kek";

    private byte[] kek = null;

    /**
     * Create a new KeyHierarchy.
     */
    public KeyHierarchy() {
    }

    /**
     * Create a new KeyHierarchy with the specified KEK.
     *
     * @param kek the KEK
     */
    public KeyHierarchy(byte[] kek) {
        this.kek = kek;
    }

    /**
     * Derive a log encryption key from the API key, tenant ID, and log name.
     *
     * @param apiKey the API key
     * @param tenantId the tenant ID
     * @param logName the log name
     * @return the log encryption key
     * @throws Exception if key derivation fails
     */
    public byte[] deriveLogEncryptionKey(String apiKey, String tenantId, String logName) throws Exception {
        String context = LOG_ENCRYPTION_KEY_CONTEXT + ":" + tenantId + ":" + logName;
        return deriveKey(apiKey.getBytes(StandardCharsets.UTF_8), context);
    }

    /**
     * Derive a log search key from the API key, tenant ID, and log name.
     *
     * @param apiKey the API key
     * @param tenantId the tenant ID
     * @param logName the log name
     * @return the log search key
     * @throws Exception if key derivation fails
     */
    public byte[] deriveLogSearchKey(String apiKey, String tenantId, String logName) throws Exception {
        String context = LOG_SEARCH_KEY_CONTEXT + ":" + tenantId + ":" + logName;
        return deriveKey(apiKey.getBytes(StandardCharsets.UTF_8), context);
    }

    /**
     * Derive a log name key from the API key and tenant ID.
     *
     * @param apiKey the API key
     * @param tenantId the tenant ID
     * @return the log name key
     * @throws Exception if key derivation fails
     */
    public byte[] deriveLogNameKey(String apiKey, String tenantId) throws Exception {
        String context = LOG_NAME_KEY_CONTEXT + ":" + tenantId;
        return deriveKey(apiKey.getBytes(StandardCharsets.UTF_8), context);
    }

    /**
     * Initialize the key hierarchy from an API key.
     *
     * @param apiKey the API key
     * @param tenantId the tenant ID
     * @throws Exception if initialization fails
     */
    public void initializeFromApiKey(String apiKey, String tenantId) throws Exception {
        try {
            // Derive KEK from API key
            this.kek = deriveKEK(apiKey, tenantId);
        } catch (Exception e) {
            throw new Exception("Failed to initialize key hierarchy from API key", e);
        }
    }

    /**
     * Derive a KEK from an API key and tenant ID.
     *
     * @param apiKey the API key
     * @param tenantId the tenant ID
     * @return the KEK
     * @throws Exception if derivation fails
     */
    public byte[] deriveKEK(String apiKey, String tenantId) throws Exception {
        String context = KEK_CONTEXT + ":" + tenantId;
        return deriveKey(apiKey.getBytes(StandardCharsets.UTF_8), context);
    }

    /**
     * Derive an API key from a KEK, tenant ID, and key ID.
     *
     * @param kek the KEK
     * @param tenantId the tenant ID
     * @param keyId the key ID
     * @return the API key
     * @throws Exception if derivation fails
     */
    public String deriveApiKey(byte[] kek, String tenantId, String keyId) throws Exception {
        try {
            String context = API_KEY_CONTEXT + ":" + tenantId + ":" + keyId;

            // Derive key
            Mac hmac = Mac.getInstance(HMAC_ALGORITHM);
            SecretKeySpec keySpec = new SecretKeySpec(kek, HMAC_ALGORITHM);
            hmac.init(keySpec);
            byte[] derivedKey = hmac.doFinal(context.getBytes(StandardCharsets.UTF_8));

            // Convert to Base64URL
            String apiKey = Base64.getUrlEncoder().withoutPadding().encodeToString(derivedKey);

            // Add key ID as prefix
            return keyId + "." + apiKey;
        } catch (Exception e) {
            throw new Exception("Failed to derive API key", e);
        }
    }

    /**
     * Derive a key from the specified key material and context.
     *
     * @param keyMaterial the key material
     * @param context the context
     * @return the derived key
     * @throws Exception if key derivation fails
     */
    private byte[] deriveKey(byte[] keyMaterial, String context) throws Exception {
        try {
            Mac hmac = Mac.getInstance(HMAC_ALGORITHM);
            SecretKeySpec keySpec = new SecretKeySpec(keyMaterial, HMAC_ALGORITHM);
            hmac.init(keySpec);
            return hmac.doFinal(context.getBytes(StandardCharsets.UTF_8));
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new Exception("Failed to derive key", e);
        }
    }
}

package com.neurallog.client.crypto;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.neurallog.client.model.EncryptedKEK;

/**
 * Provides cryptographic operations for the NeuralLog client.
 */
public class CryptoService {

    private static final String AES_GCM_ALGORITHM = "AES/GCM/NoPadding";
    private static final String HMAC_ALGORITHM = "HmacSHA256";
    private static final int GCM_TAG_LENGTH = 128;
    private static final int GCM_IV_LENGTH = 12;

    private final SecureRandom secureRandom;

    /**
     * Create a new crypto service.
     */
    public CryptoService() {
        this.secureRandom = new SecureRandom();
    }

    /**
     * Encrypt log data.
     *
     * @param data the data to encrypt
     * @param key the encryption key
     * @return the encrypted data
     * @throws Exception if encryption fails
     */
    public Map<String, Object> encryptLogData(Map<String, Object> data, byte[] key) throws Exception {
        // Convert data to JSON string
        String jsonData = new com.fasterxml.jackson.databind.ObjectMapper().writeValueAsString(data);

        // Generate IV
        byte[] iv = new byte[GCM_IV_LENGTH];
        secureRandom.nextBytes(iv);

        // Create cipher
        Cipher cipher = Cipher.getInstance(AES_GCM_ALGORITHM);
        SecretKey secretKey = new SecretKeySpec(key, "AES");
        GCMParameterSpec parameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);

        // Encrypt
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, parameterSpec);
        byte[] encryptedData = cipher.doFinal(jsonData.getBytes(StandardCharsets.UTF_8));

        // Create result
        Map<String, Object> result = new HashMap<>();
        result.put("iv", Base64.getEncoder().encodeToString(iv));
        result.put("data", Base64.getEncoder().encodeToString(encryptedData));
        result.put("algorithm", "aes-256-gcm");

        return result;
    }

    /**
     * Decrypt log data.
     *
     * @param encryptedData the encrypted data
     * @param key the decryption key
     * @return the decrypted data
     * @throws Exception if decryption fails
     */
    public Map<String, Object> decryptLogData(Map<String, Object> encryptedData, byte[] key) throws Exception {
        // Get IV and encrypted data
        byte[] iv = Base64.getDecoder().decode((String) encryptedData.get("iv"));
        byte[] data = Base64.getDecoder().decode((String) encryptedData.get("data"));

        // Create cipher
        Cipher cipher = Cipher.getInstance(AES_GCM_ALGORITHM);
        SecretKey secretKey = new SecretKeySpec(key, "AES");
        GCMParameterSpec parameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);

        // Decrypt
        cipher.init(Cipher.DECRYPT_MODE, secretKey, parameterSpec);
        byte[] decryptedData = cipher.doFinal(data);

        // Parse JSON
        String jsonData = new String(decryptedData, StandardCharsets.UTF_8);
        return new com.fasterxml.jackson.databind.ObjectMapper().readValue(jsonData, Map.class);
    }

    /**
     * Generate search tokens for the specified query.
     *
     * @param query the search query
     * @param searchKey the search key
     * @return the search tokens
     * @throws Exception if token generation fails
     */
    public List<String> generateSearchTokens(String query, byte[] searchKey) throws Exception {
        List<String> tokens = new ArrayList<>();

        // Split query into words
        String[] words = query.toLowerCase().split("\\s+");

        // Generate token for each word
        for (String word : words) {
            if (word.isEmpty()) {
                continue;
            }

            // Generate token
            Mac hmac = Mac.getInstance(HMAC_ALGORITHM);
            SecretKeySpec keySpec = new SecretKeySpec(searchKey, HMAC_ALGORITHM);
            hmac.init(keySpec);
            byte[] tokenBytes = hmac.doFinal(word.getBytes(StandardCharsets.UTF_8));

            // Encode token
            String token = Base64.getEncoder().encodeToString(tokenBytes);
            tokens.add(token);
        }

        return tokens;
    }

    /**
     * Encrypt a log name.
     *
     * @param logName the log name
     * @param logNameKey the log name key
     * @return the encrypted log name
     * @throws Exception if encryption fails
     */
    public String encryptLogName(String logName, byte[] logNameKey) throws Exception {
        // Generate IV
        byte[] iv = new byte[GCM_IV_LENGTH];
        secureRandom.nextBytes(iv);

        // Create cipher
        Cipher cipher = Cipher.getInstance(AES_GCM_ALGORITHM);
        SecretKey secretKey = new SecretKeySpec(logNameKey, "AES");
        GCMParameterSpec parameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);

        // Encrypt
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, parameterSpec);
        byte[] encryptedData = cipher.doFinal(logName.getBytes(StandardCharsets.UTF_8));

        // Combine IV and encrypted data
        byte[] combined = new byte[iv.length + encryptedData.length];
        System.arraycopy(iv, 0, combined, 0, iv.length);
        System.arraycopy(encryptedData, 0, combined, iv.length, encryptedData.length);

        // Encode
        return Base64.getUrlEncoder().withoutPadding().encodeToString(combined);
    }

    /**
     * Decrypt a log name.
     *
     * @param encryptedLogName the encrypted log name
     * @param logNameKey the log name key
     * @return the decrypted log name
     * @throws Exception if decryption fails
     */
    public String decryptLogName(String encryptedLogName, byte[] logNameKey) throws Exception {
        // Decode
        byte[] combined = Base64.getUrlDecoder().decode(encryptedLogName);

        // Extract IV and encrypted data
        byte[] iv = new byte[GCM_IV_LENGTH];
        byte[] encryptedData = new byte[combined.length - GCM_IV_LENGTH];
        System.arraycopy(combined, 0, iv, 0, GCM_IV_LENGTH);
        System.arraycopy(combined, GCM_IV_LENGTH, encryptedData, 0, encryptedData.length);

        // Create cipher
        Cipher cipher = Cipher.getInstance(AES_GCM_ALGORITHM);
        SecretKey secretKey = new SecretKeySpec(logNameKey, "AES");
        GCMParameterSpec parameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);

        // Decrypt
        cipher.init(Cipher.DECRYPT_MODE, secretKey, parameterSpec);
        byte[] decryptedData = cipher.doFinal(encryptedData);

        // Decode
        return new String(decryptedData, StandardCharsets.UTF_8);
    }

    /**
     * Generate a search token for the specified term.
     *
     * @param term the search term
     * @param searchKey the search key
     * @return the search token
     * @throws Exception if token generation fails
     */
    public String generateSearchToken(String term, byte[] searchKey) throws Exception {
        // Generate token
        Mac hmac = Mac.getInstance(HMAC_ALGORITHM);
        SecretKeySpec keySpec = new SecretKeySpec(searchKey, HMAC_ALGORITHM);
        hmac.init(keySpec);
        byte[] tokenBytes = hmac.doFinal(term.getBytes(StandardCharsets.UTF_8));

        // Encode token
        return Base64.getEncoder().encodeToString(tokenBytes);
    }

    /**
     * Derive a master secret from a username and password.
     *
     * @param username the username
     * @param password the password
     * @return the master secret
     * @throws Exception if derivation fails
     */
    public String deriveMasterSecret(String username, String password) throws Exception {
        try {
            // Create salt from username
            byte[] salt = username.getBytes(StandardCharsets.UTF_8);

            // Create key spec
            KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 100000, 256);

            // Derive key using PBKDF2
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            byte[] keyBytes = factory.generateSecret(spec).getEncoded();

            // Convert to Base64 for storage
            return Base64.getEncoder().encodeToString(keyBytes);
        } catch (Exception e) {
            throw new Exception("Failed to derive master secret", e);
        }
    }

    /**
     * Generate a Key Encryption Key (KEK).
     *
     * @return the KEK
     * @throws Exception if generation fails
     */
    public byte[] generateKEK() throws Exception {
        try {
            // Generate a random key
            byte[] key = new byte[32];
            secureRandom.nextBytes(key);
            return key;
        } catch (Exception e) {
            throw new Exception("Failed to generate KEK", e);
        }
    }

    /**
     * Encrypt a Key Encryption Key (KEK) with a master secret.
     *
     * @param kek the KEK
     * @param masterSecret the master secret
     * @return the encrypted KEK
     * @throws Exception if encryption fails
     */
    public EncryptedKEK encryptKEK(byte[] kek, String masterSecret) throws Exception {
        try {
            // Decode master secret
            byte[] masterKeyBytes = Base64.getDecoder().decode(masterSecret);

            // Create master key
            SecretKey masterKey = new SecretKeySpec(masterKeyBytes, "AES");

            // Generate IV
            byte[] iv = new byte[GCM_IV_LENGTH];
            secureRandom.nextBytes(iv);

            // Create cipher
            Cipher cipher = Cipher.getInstance(AES_GCM_ALGORITHM);
            GCMParameterSpec parameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);

            // Encrypt KEK
            cipher.init(Cipher.ENCRYPT_MODE, masterKey, parameterSpec);
            byte[] encryptedKEK = cipher.doFinal(kek);

            // Convert to Base64
            String encryptedKEKBase64 = Base64.getEncoder().encodeToString(encryptedKEK);
            String ivBase64 = Base64.getEncoder().encodeToString(iv);

            // Return encrypted KEK
            EncryptedKEK result = new EncryptedKEK();
            result.setEncrypted(true);
            result.setAlgorithm("aes-256-gcm");
            result.setIv(ivBase64);
            result.setData(encryptedKEKBase64);

            return result;
        } catch (Exception e) {
            throw new Exception("Failed to encrypt KEK", e);
        }
    }

    /**
     * Decrypt a Key Encryption Key (KEK) with a master secret.
     *
     * @param encryptedKEK the encrypted KEK
     * @param masterSecret the master secret
     * @return the decrypted KEK
     * @throws Exception if decryption fails
     */
    public byte[] decryptKEK(EncryptedKEK encryptedKEK, String masterSecret) throws Exception {
        try {
            // Decode master secret
            byte[] masterKeyBytes = Base64.getDecoder().decode(masterSecret);

            // Create master key
            SecretKey masterKey = new SecretKeySpec(masterKeyBytes, "AES");

            // Get IV and encrypted data
            byte[] iv = Base64.getDecoder().decode(encryptedKEK.getIv());
            byte[] encryptedData = Base64.getDecoder().decode(encryptedKEK.getData());

            // Create cipher
            Cipher cipher = Cipher.getInstance(AES_GCM_ALGORITHM);
            GCMParameterSpec parameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);

            // Decrypt KEK
            cipher.init(Cipher.DECRYPT_MODE, masterKey, parameterSpec);
            byte[] decryptedKEK = cipher.doFinal(encryptedData);

            // Return decrypted KEK
            return decryptedKEK;
        } catch (Exception e) {
            throw new Exception("Failed to decrypt KEK", e);
        }
    }

    /**
     * Generate a zero-knowledge proof for an API key.
     *
     * @param apiKey the API key
     * @return the proof
     * @throws Exception if proof generation fails
     */
    public String generateApiKeyProof(String apiKey) throws Exception {
        try {
            // Generate a random nonce
            byte[] nonce = new byte[16];
            secureRandom.nextBytes(nonce);
            String nonceBase64 = Base64.getEncoder().encodeToString(nonce);

            // Generate proof
            Mac hmac = Mac.getInstance(HMAC_ALGORITHM);
            SecretKeySpec keySpec = new SecretKeySpec(apiKey.getBytes(StandardCharsets.UTF_8), HMAC_ALGORITHM);
            hmac.init(keySpec);
            byte[] proofBytes = hmac.doFinal(nonceBase64.getBytes(StandardCharsets.UTF_8));

            // Convert to Base64
            String proofBase64 = Base64.getEncoder().encodeToString(proofBytes);

            // Return proof and nonce as JSON
            return String.format("{\"nonce\":\"%s\",\"proof\":\"%s\"}", nonceBase64, proofBase64);
        } catch (Exception e) {
            throw new Exception("Failed to generate API key proof", e);
        }
    }
}

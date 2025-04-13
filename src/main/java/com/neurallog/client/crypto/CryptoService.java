package com.neurallog.client.crypto;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

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
}

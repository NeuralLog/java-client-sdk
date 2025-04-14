package com.neurallog.client.api;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.neurallog.client.model.EncryptedKEK;
import okhttp3.*;

import java.io.IOException;

/**
 * Service for managing Key Encryption Keys (KEKs).
 */
public class KekService {

    private final String baseUrl;
    private final OkHttpClient httpClient;
    private final ObjectMapper objectMapper;
    
    /**
     * Create a new KEK service with the specified base URL and object mapper.
     * 
     * @param baseUrl the base URL of the auth service
     * @param objectMapper the object mapper for JSON serialization/deserialization
     */
    public KekService(String baseUrl, ObjectMapper objectMapper) {
        this.baseUrl = baseUrl;
        this.objectMapper = objectMapper;
        
        this.httpClient = new OkHttpClient.Builder()
            .build();
    }
    
    /**
     * Get the encrypted KEK for the authenticated user.
     * 
     * @param authToken the authentication token
     * @return the encrypted KEK, or null if not found
     * @throws IOException if the request fails
     */
    public EncryptedKEK getEncryptedKEK(String authToken) throws IOException {
        Request request = new Request.Builder()
            .url(baseUrl + "/kek")
            .header("Authorization", "Bearer " + authToken)
            .get()
            .build();
        
        try (Response response = httpClient.newCall(request).execute()) {
            if (response.code() == 404) {
                return null;
            }
            
            if (!response.isSuccessful()) {
                throw new IOException("Failed to get encrypted KEK: " + response.code());
            }
            
            String responseBody = response.body().string();
            return objectMapper.readValue(responseBody, EncryptedKEK.class);
        }
    }
    
    /**
     * Create an encrypted KEK for the authenticated user.
     * 
     * @param encryptedKEK the encrypted KEK
     * @param authToken the authentication token
     * @throws IOException if the request fails
     */
    public void createEncryptedKEK(EncryptedKEK encryptedKEK, String authToken) throws IOException {
        RequestBody body = RequestBody.create(
            objectMapper.writeValueAsString(encryptedKEK),
            MediaType.parse("application/json")
        );
        
        Request request = new Request.Builder()
            .url(baseUrl + "/kek")
            .header("Authorization", "Bearer " + authToken)
            .post(body)
            .build();
        
        try (Response response = httpClient.newCall(request).execute()) {
            if (!response.isSuccessful()) {
                throw new IOException("Failed to create encrypted KEK: " + response.code());
            }
        }
    }
    
    /**
     * Update the encrypted KEK for the authenticated user.
     * 
     * @param encryptedKEK the encrypted KEK
     * @param authToken the authentication token
     * @throws IOException if the request fails
     */
    public void updateEncryptedKEK(EncryptedKEK encryptedKEK, String authToken) throws IOException {
        RequestBody body = RequestBody.create(
            objectMapper.writeValueAsString(encryptedKEK),
            MediaType.parse("application/json")
        );
        
        Request request = new Request.Builder()
            .url(baseUrl + "/kek")
            .header("Authorization", "Bearer " + authToken)
            .put(body)
            .build();
        
        try (Response response = httpClient.newCall(request).execute()) {
            if (!response.isSuccessful()) {
                throw new IOException("Failed to update encrypted KEK: " + response.code());
            }
        }
    }
}

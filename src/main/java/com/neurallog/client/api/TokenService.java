package com.neurallog.client.api;

import com.fasterxml.jackson.databind.ObjectMapper;
import okhttp3.*;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

/**
 * Service for managing resource tokens.
 */
public class TokenService {

    private final String baseUrl;
    private final OkHttpClient httpClient;
    private final ObjectMapper objectMapper;
    
    /**
     * Create a new token service with the specified base URL and object mapper.
     * 
     * @param baseUrl the base URL of the auth service
     * @param objectMapper the object mapper for JSON serialization/deserialization
     */
    public TokenService(String baseUrl, ObjectMapper objectMapper) {
        this.baseUrl = baseUrl;
        this.objectMapper = objectMapper;
        
        this.httpClient = new OkHttpClient.Builder()
            .build();
    }
    
    /**
     * Get a resource token for the specified resource.
     * 
     * @param resource the resource path
     * @param authToken the authentication token
     * @return the resource token
     * @throws IOException if the request fails
     */
    public String getResourceToken(String resource, String authToken) throws IOException {
        Map<String, String> requestBody = new HashMap<>();
        requestBody.put("resource", resource);
        
        RequestBody body = RequestBody.create(
            objectMapper.writeValueAsString(requestBody),
            MediaType.parse("application/json")
        );
        
        Request request = new Request.Builder()
            .url(baseUrl + "/token")
            .header("Authorization", "Bearer " + authToken)
            .post(body)
            .build();
        
        try (Response response = httpClient.newCall(request).execute()) {
            if (!response.isSuccessful()) {
                throw new IOException("Failed to get resource token: " + response.code());
            }
            
            String responseBody = response.body().string();
            Map<String, Object> responseMap = objectMapper.readValue(responseBody, Map.class);
            
            return (String) responseMap.get("token");
        }
    }
    
    /**
     * Get a resource token for the specified resource using an API key.
     * 
     * @param resource the resource path
     * @param apiKey the API key
     * @param proof the zero-knowledge proof for the API key
     * @return the resource token
     * @throws IOException if the request fails
     */
    public String getResourceTokenWithApiKey(String resource, String apiKey, String proof) throws IOException {
        Map<String, String> requestBody = new HashMap<>();
        requestBody.put("resource", resource);
        requestBody.put("proof", proof);
        
        RequestBody body = RequestBody.create(
            objectMapper.writeValueAsString(requestBody),
            MediaType.parse("application/json")
        );
        
        Request request = new Request.Builder()
            .url(baseUrl + "/token/api-key")
            .header("Authorization", "Bearer " + apiKey)
            .post(body)
            .build();
        
        try (Response response = httpClient.newCall(request).execute()) {
            if (!response.isSuccessful()) {
                throw new IOException("Failed to get resource token with API key: " + response.code());
            }
            
            String responseBody = response.body().string();
            Map<String, Object> responseMap = objectMapper.readValue(responseBody, Map.class);
            
            return (String) responseMap.get("token");
        }
    }
    
    /**
     * Verify a resource token.
     * 
     * @param token the resource token
     * @return true if the token is valid
     * @throws IOException if the request fails
     */
    public boolean verifyResourceToken(String token) throws IOException {
        Map<String, String> requestBody = new HashMap<>();
        requestBody.put("token", token);
        
        RequestBody body = RequestBody.create(
            objectMapper.writeValueAsString(requestBody),
            MediaType.parse("application/json")
        );
        
        Request request = new Request.Builder()
            .url(baseUrl + "/token/verify")
            .post(body)
            .build();
        
        try (Response response = httpClient.newCall(request).execute()) {
            if (!response.isSuccessful()) {
                return false;
            }
            
            String responseBody = response.body().string();
            Map<String, Object> responseMap = objectMapper.readValue(responseBody, Map.class);
            
            return (boolean) responseMap.getOrDefault("valid", false);
        }
    }
}

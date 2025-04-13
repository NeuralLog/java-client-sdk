package com.neurallog.client.api;

import com.fasterxml.jackson.databind.ObjectMapper;
import okhttp3.*;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;

/**
 * Service for interacting with the NeuralLog auth service.
 */
public class AuthService {

    private final String baseUrl;
    private final OkHttpClient httpClient;
    private final ObjectMapper objectMapper;
    
    /**
     * Create a new auth service with the specified base URL and object mapper.
     * 
     * @param baseUrl the base URL of the auth service
     * @param objectMapper the object mapper for JSON serialization/deserialization
     */
    public AuthService(String baseUrl, ObjectMapper objectMapper) {
        this.baseUrl = baseUrl;
        this.objectMapper = objectMapper;
        
        this.httpClient = new OkHttpClient.Builder()
            .connectTimeout(10, TimeUnit.SECONDS)
            .readTimeout(30, TimeUnit.SECONDS)
            .writeTimeout(30, TimeUnit.SECONDS)
            .build();
    }
    
    /**
     * Validate an API key.
     * 
     * @param apiKey the API key to validate
     * @param tenantId the tenant ID
     * @return true if the API key is valid
     * @throws IOException if the request fails
     */
    public boolean validateApiKey(String apiKey, String tenantId) throws IOException {
        HttpUrl url = HttpUrl.parse(baseUrl + "/auth/validate-api-key")
            .newBuilder()
            .addQueryParameter("tenant_id", tenantId)
            .build();
        
        Map<String, String> requestBody = new HashMap<>();
        requestBody.put("api_key", apiKey);
        
        RequestBody body = RequestBody.create(
            objectMapper.writeValueAsString(requestBody),
            MediaType.parse("application/json")
        );
        
        Request request = new Request.Builder()
            .url(url)
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
    
    /**
     * Get a resource token for the specified resource.
     * 
     * @param apiKey the API key
     * @param tenantId the tenant ID
     * @param resource the resource path
     * @return the resource token
     * @throws IOException if the request fails
     */
    public String getResourceToken(String apiKey, String tenantId, String resource) throws IOException {
        HttpUrl url = HttpUrl.parse(baseUrl + "/auth/resource-token")
            .newBuilder()
            .addQueryParameter("tenant_id", tenantId)
            .addQueryParameter("resource", resource)
            .build();
        
        Request request = new Request.Builder()
            .url(url)
            .header("Authorization", "Bearer " + apiKey)
            .get()
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
}

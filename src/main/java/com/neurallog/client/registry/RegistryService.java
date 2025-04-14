package com.neurallog.client.registry;

import com.fasterxml.jackson.databind.ObjectMapper;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;

import java.io.IOException;
import java.util.concurrent.TimeUnit;

/**
 * Service for interacting with the NeuralLog registry.
 */
public class RegistryService {

    private final String registryUrl;
    private final OkHttpClient httpClient;
    private final ObjectMapper objectMapper;
    
    /**
     * Create a new registry service with the specified registry URL.
     * 
     * @param registryUrl the registry URL
     * @param objectMapper the object mapper for JSON serialization/deserialization
     */
    public RegistryService(String registryUrl, ObjectMapper objectMapper) {
        this.registryUrl = registryUrl;
        this.objectMapper = objectMapper;
        
        this.httpClient = new OkHttpClient.Builder()
            .connectTimeout(10, TimeUnit.SECONDS)
            .readTimeout(30, TimeUnit.SECONDS)
            .writeTimeout(30, TimeUnit.SECONDS)
            .build();
    }
    
    /**
     * Get tenant endpoints from the registry.
     * 
     * @return the tenant endpoints
     * @throws IOException if the request fails
     */
    public TenantEndpoints getEndpoints() throws IOException {
        Request request = new Request.Builder()
            .url(registryUrl + "/endpoints")
            .get()
            .build();
        
        try (Response response = httpClient.newCall(request).execute()) {
            if (!response.isSuccessful()) {
                throw new IOException("Failed to get tenant endpoints: " + response.code());
            }
            
            String responseBody = response.body().string();
            return objectMapper.readValue(responseBody, TenantEndpoints.class);
        }
    }
}

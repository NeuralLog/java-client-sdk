package com.neurallog.client.api;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.neurallog.client.model.ApiKeyInfo;
import com.neurallog.client.model.CreateApiKeyRequest;
import com.neurallog.client.model.EncryptedKEK;
import com.neurallog.client.model.LoginResponse;
import com.neurallog.client.model.LoginRequest;
import okhttp3.*;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
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
        return validateApiKey(apiKey, tenantId, null);
    }

    /**
     * Validate an API key with a zero-knowledge proof.
     *
     * @param apiKey the API key to validate
     * @param tenantId the tenant ID
     * @param proof the zero-knowledge proof
     * @return true if the API key is valid
     * @throws IOException if the request fails
     */
    public boolean validateApiKey(String apiKey, String tenantId, String proof) throws IOException {
        HttpUrl url = HttpUrl.parse(baseUrl + "/auth/validate-api-key")
            .newBuilder()
            .addQueryParameter("tenant_id", tenantId)
            .build();

        Map<String, Object> requestBody = new HashMap<>();
        requestBody.put("api_key", apiKey);

        if (proof != null) {
            requestBody.put("proof", proof);
        }

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

    /**
     * Login with username and password.
     *
     * @param username the username
     * @param password the password
     * @param tenantId the tenant ID
     * @return the login response containing the API key
     * @throws IOException if the request fails
     */
    public LoginResponse login(String username, String password, String tenantId) throws IOException {
        LoginRequest loginRequest = new LoginRequest();
        loginRequest.setUsername(username);
        loginRequest.setPassword(password);
        loginRequest.setTenantId(tenantId);

        RequestBody body = RequestBody.create(
            objectMapper.writeValueAsString(loginRequest),
            MediaType.parse("application/json")
        );

        Request request = new Request.Builder()
            .url(baseUrl + "/auth/login")
            .post(body)
            .build();

        try (Response response = httpClient.newCall(request).execute()) {
            if (!response.isSuccessful()) {
                throw new IOException("Failed to login: " + response.code());
            }

            String responseBody = response.body().string();
            return objectMapper.readValue(responseBody, LoginResponse.class);
        }
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

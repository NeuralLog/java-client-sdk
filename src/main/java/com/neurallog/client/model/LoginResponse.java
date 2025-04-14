package com.neurallog.client.model;

/**
 * Represents a login response from the auth service.
 */
public class LoginResponse {

    private boolean success;
    private String token;
    private String userId;
    private String tenantId;

    /**
     * Create a new LoginResponse.
     */
    public LoginResponse() {
    }

    /**
     * Create a new LoginResponse with the specified parameters.
     *
     * @param success whether the login was successful
     * @param token the authentication token
     * @param userId the user ID
     * @param tenantId the tenant ID
     */
    public LoginResponse(boolean success, String token, String userId, String tenantId) {
        this.success = success;
        this.token = token;
        this.userId = userId;
        this.tenantId = tenantId;
    }

    /**
     * Get whether the login was successful.
     *
     * @return whether the login was successful
     */
    public boolean isSuccess() {
        return success;
    }

    /**
     * Set whether the login was successful.
     *
     * @param success whether the login was successful
     */
    public void setSuccess(boolean success) {
        this.success = success;
    }

    /**
     * Get the authentication token.
     *
     * @return the authentication token
     */
    public String getToken() {
        return token;
    }

    /**
     * Set the authentication token.
     *
     * @param token the authentication token
     */
    public void setToken(String token) {
        this.token = token;
    }

    /**
     * Get the user ID.
     *
     * @return the user ID
     */
    public String getUserId() {
        return userId;
    }

    /**
     * Set the user ID.
     *
     * @param userId the user ID
     */
    public void setUserId(String userId) {
        this.userId = userId;
    }

    /**
     * Get the tenant ID.
     *
     * @return the tenant ID
     */
    public String getTenantId() {
        return tenantId;
    }

    /**
     * Set the tenant ID.
     *
     * @param tenantId the tenant ID
     */
    public void setTenantId(String tenantId) {
        this.tenantId = tenantId;
    }
}

package com.neurallog.client.model;

/**
 * Request for logging in with username and password.
 */
public class LoginRequest {
    
    private String username;
    private String password;
    private String tenantId;
    
    /**
     * Get the username.
     * 
     * @return the username
     */
    public String getUsername() {
        return username;
    }
    
    /**
     * Set the username.
     * 
     * @param username the username
     */
    public void setUsername(String username) {
        this.username = username;
    }
    
    /**
     * Get the password.
     * 
     * @return the password
     */
    public String getPassword() {
        return password;
    }
    
    /**
     * Set the password.
     * 
     * @param password the password
     */
    public void setPassword(String password) {
        this.password = password;
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

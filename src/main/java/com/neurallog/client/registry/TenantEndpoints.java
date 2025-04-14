package com.neurallog.client.registry;

/**
 * Tenant endpoints returned by the registry.
 */
public class TenantEndpoints {
    
    private String tenantId;
    private String authUrl;
    private String serverUrl;
    private String webUrl;
    private String apiVersion;
    
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
    
    /**
     * Get the auth service URL.
     * 
     * @return the auth service URL
     */
    public String getAuthUrl() {
        return authUrl;
    }
    
    /**
     * Set the auth service URL.
     * 
     * @param authUrl the auth service URL
     */
    public void setAuthUrl(String authUrl) {
        this.authUrl = authUrl;
    }
    
    /**
     * Get the server URL.
     * 
     * @return the server URL
     */
    public String getServerUrl() {
        return serverUrl;
    }
    
    /**
     * Set the server URL.
     * 
     * @param serverUrl the server URL
     */
    public void setServerUrl(String serverUrl) {
        this.serverUrl = serverUrl;
    }
    
    /**
     * Get the web URL.
     * 
     * @return the web URL
     */
    public String getWebUrl() {
        return webUrl;
    }
    
    /**
     * Set the web URL.
     * 
     * @param webUrl the web URL
     */
    public void setWebUrl(String webUrl) {
        this.webUrl = webUrl;
    }
    
    /**
     * Get the API version.
     * 
     * @return the API version
     */
    public String getApiVersion() {
        return apiVersion;
    }
    
    /**
     * Set the API version.
     * 
     * @param apiVersion the API version
     */
    public void setApiVersion(String apiVersion) {
        this.apiVersion = apiVersion;
    }
}

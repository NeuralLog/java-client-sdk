package com.neurallog.client;

/**
 * Configuration for the NeuralLog client.
 */
public class NeuralLogClientConfig {

    private String tenantId = "default";
    private String authUrl = "http://localhost:3000";
    private String logsUrl = "http://localhost:3030";
    private String registryUrl = null;
    private String webUrl = null;

    /**
     * Create a new client configuration with default values.
     */
    public NeuralLogClientConfig() {
        // Use default values
    }

    /**
     * Create a new client configuration with the specified tenant ID.
     *
     * @param tenantId the tenant ID
     */
    public NeuralLogClientConfig(String tenantId) {
        this.tenantId = tenantId;
    }

    /**
     * Create a new client configuration with the specified tenant ID, auth URL, and logs URL.
     *
     * @param tenantId the tenant ID
     * @param authUrl the auth service URL
     * @param logsUrl the logs service URL
     */
    public NeuralLogClientConfig(String tenantId, String authUrl, String logsUrl) {
        this.tenantId = tenantId;
        this.authUrl = authUrl;
        this.logsUrl = logsUrl;
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
     * @return this configuration instance for chaining
     */
    public NeuralLogClientConfig setTenantId(String tenantId) {
        this.tenantId = tenantId;
        return this;
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
     * @return this configuration instance for chaining
     */
    public NeuralLogClientConfig setAuthUrl(String authUrl) {
        this.authUrl = authUrl;
        return this;
    }

    /**
     * Get the logs service URL.
     *
     * @return the logs service URL
     */
    public String getLogsUrl() {
        return logsUrl;
    }

    /**
     * Set the logs service URL.
     *
     * @param logsUrl the logs service URL
     * @return this configuration instance for chaining
     */
    public NeuralLogClientConfig setLogsUrl(String logsUrl) {
        this.logsUrl = logsUrl;
        return this;
    }

    /**
     * Get the registry URL.
     *
     * @return the registry URL
     */
    public String getRegistryUrl() {
        return registryUrl;
    }

    /**
     * Set the registry URL.
     *
     * @param registryUrl the registry URL
     * @return this configuration instance for chaining
     */
    public NeuralLogClientConfig setRegistryUrl(String registryUrl) {
        this.registryUrl = registryUrl;
        return this;
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
     * @return this configuration instance for chaining
     */
    public NeuralLogClientConfig setWebUrl(String webUrl) {
        this.webUrl = webUrl;
        return this;
    }
}

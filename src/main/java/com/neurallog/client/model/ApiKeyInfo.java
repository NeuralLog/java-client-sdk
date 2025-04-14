package com.neurallog.client.model;

import java.time.Instant;
import java.util.List;

/**
 * Represents information about an API key.
 */
public class ApiKeyInfo {

    private String id;
    private String name;
    private List<String> permissions;
    private Instant createdAt;
    private Instant lastUsedAt;

    /**
     * Create a new ApiKeyInfo.
     */
    public ApiKeyInfo() {
    }

    /**
     * Create a new ApiKeyInfo with the specified parameters.
     *
     * @param id the API key ID
     * @param name the API key name
     * @param permissions the API key permissions
     * @param createdAt the API key creation date
     * @param lastUsedAt the API key last used date
     */
    public ApiKeyInfo(String id, String name, List<String> permissions, Instant createdAt, Instant lastUsedAt) {
        this.id = id;
        this.name = name;
        this.permissions = permissions;
        this.createdAt = createdAt;
        this.lastUsedAt = lastUsedAt;
    }

    /**
     * Get the API key ID.
     *
     * @return the API key ID
     */
    public String getId() {
        return id;
    }

    /**
     * Set the API key ID.
     *
     * @param id the API key ID
     */
    public void setId(String id) {
        this.id = id;
    }

    /**
     * Get the API key name.
     *
     * @return the API key name
     */
    public String getName() {
        return name;
    }

    /**
     * Set the API key name.
     *
     * @param name the API key name
     */
    public void setName(String name) {
        this.name = name;
    }

    /**
     * Get the API key permissions.
     *
     * @return the API key permissions
     */
    public List<String> getPermissions() {
        return permissions;
    }

    /**
     * Set the API key permissions.
     *
     * @param permissions the API key permissions
     */
    public void setPermissions(List<String> permissions) {
        this.permissions = permissions;
    }

    /**
     * Get the API key creation date.
     *
     * @return the API key creation date
     */
    public Instant getCreatedAt() {
        return createdAt;
    }

    /**
     * Set the API key creation date.
     *
     * @param createdAt the API key creation date
     */
    public void setCreatedAt(Instant createdAt) {
        this.createdAt = createdAt;
    }

    /**
     * Get the API key last used date.
     *
     * @return the API key last used date
     */
    public Instant getLastUsedAt() {
        return lastUsedAt;
    }

    /**
     * Set the API key last used date.
     *
     * @param lastUsedAt the API key last used date
     */
    public void setLastUsedAt(Instant lastUsedAt) {
        this.lastUsedAt = lastUsedAt;
    }
}

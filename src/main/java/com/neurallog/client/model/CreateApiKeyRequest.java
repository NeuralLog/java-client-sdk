package com.neurallog.client.model;

import java.util.List;

/**
 * Represents a request to create an API key.
 */
public class CreateApiKeyRequest {

    private String name;
    private String keyId;
    private String verificationHash;
    private List<String> permissions;

    /**
     * Create a new CreateApiKeyRequest.
     */
    public CreateApiKeyRequest() {
    }

    /**
     * Create a new CreateApiKeyRequest with the specified parameters.
     *
     * @param name the API key name
     * @param keyId the API key ID
     * @param verificationHash the API key verification hash
     * @param permissions the API key permissions
     */
    public CreateApiKeyRequest(String name, String keyId, String verificationHash, List<String> permissions) {
        this.name = name;
        this.keyId = keyId;
        this.verificationHash = verificationHash;
        this.permissions = permissions;
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
     * Get the API key ID.
     *
     * @return the API key ID
     */
    public String getKeyId() {
        return keyId;
    }

    /**
     * Set the API key ID.
     *
     * @param keyId the API key ID
     */
    public void setKeyId(String keyId) {
        this.keyId = keyId;
    }

    /**
     * Get the API key verification hash.
     *
     * @return the API key verification hash
     */
    public String getVerificationHash() {
        return verificationHash;
    }

    /**
     * Set the API key verification hash.
     *
     * @param verificationHash the API key verification hash
     */
    public void setVerificationHash(String verificationHash) {
        this.verificationHash = verificationHash;
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
}

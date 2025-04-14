package com.neurallog.client.model;

/**
 * Represents an encrypted Key Encryption Key (KEK).
 */
public class EncryptedKEK {

    private boolean encrypted;
    private String algorithm;
    private String iv;
    private String data;

    /**
     * Create a new EncryptedKEK.
     */
    public EncryptedKEK() {
    }

    /**
     * Create a new EncryptedKEK with the specified parameters.
     *
     * @param encrypted whether the KEK is encrypted
     * @param algorithm the encryption algorithm
     * @param iv the initialization vector
     * @param data the encrypted data
     */
    public EncryptedKEK(boolean encrypted, String algorithm, String iv, String data) {
        this.encrypted = encrypted;
        this.algorithm = algorithm;
        this.iv = iv;
        this.data = data;
    }

    /**
     * Get whether the KEK is encrypted.
     *
     * @return whether the KEK is encrypted
     */
    public boolean isEncrypted() {
        return encrypted;
    }

    /**
     * Set whether the KEK is encrypted.
     *
     * @param encrypted whether the KEK is encrypted
     */
    public void setEncrypted(boolean encrypted) {
        this.encrypted = encrypted;
    }

    /**
     * Get the encryption algorithm.
     *
     * @return the encryption algorithm
     */
    public String getAlgorithm() {
        return algorithm;
    }

    /**
     * Set the encryption algorithm.
     *
     * @param algorithm the encryption algorithm
     */
    public void setAlgorithm(String algorithm) {
        this.algorithm = algorithm;
    }

    /**
     * Get the initialization vector.
     *
     * @return the initialization vector
     */
    public String getIv() {
        return iv;
    }

    /**
     * Set the initialization vector.
     *
     * @param iv the initialization vector
     */
    public void setIv(String iv) {
        this.iv = iv;
    }

    /**
     * Get the encrypted data.
     *
     * @return the encrypted data
     */
    public String getData() {
        return data;
    }

    /**
     * Set the encrypted data.
     *
     * @param data the encrypted data
     */
    public void setData(String data) {
        this.data = data;
    }
}

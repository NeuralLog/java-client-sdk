package com.neurallog.client.model;

import java.time.Instant;
import java.util.Map;

/**
 * Represents a log entry in the NeuralLog system.
 */
public class LogEntry {

    private String id;
    private Instant timestamp;
    private Map<String, Object> data;
    private boolean encrypted;
    
    /**
     * Create a new log entry.
     */
    public LogEntry() {
        // Default constructor
    }
    
    /**
     * Get the log entry ID.
     * 
     * @return the log entry ID
     */
    public String getId() {
        return id;
    }
    
    /**
     * Set the log entry ID.
     * 
     * @param id the log entry ID
     */
    public void setId(String id) {
        this.id = id;
    }
    
    /**
     * Get the log entry timestamp.
     * 
     * @return the log entry timestamp
     */
    public Instant getTimestamp() {
        return timestamp;
    }
    
    /**
     * Set the log entry timestamp.
     * 
     * @param timestamp the log entry timestamp
     */
    public void setTimestamp(Instant timestamp) {
        this.timestamp = timestamp;
    }
    
    /**
     * Get the log entry data.
     * 
     * @return the log entry data
     */
    public Map<String, Object> getData() {
        return data;
    }
    
    /**
     * Set the log entry data.
     * 
     * @param data the log entry data
     */
    public void setData(Map<String, Object> data) {
        this.data = data;
    }
    
    /**
     * Check if the log entry is encrypted.
     * 
     * @return true if the log entry is encrypted
     */
    public boolean isEncrypted() {
        return encrypted;
    }
    
    /**
     * Set whether the log entry is encrypted.
     * 
     * @param encrypted true if the log entry is encrypted
     */
    public void setEncrypted(boolean encrypted) {
        this.encrypted = encrypted;
    }
}

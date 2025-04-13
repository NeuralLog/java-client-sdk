package com.neurallog.client.model;

import java.time.Instant;
import java.util.List;

/**
 * Options for searching logs.
 */
public class SearchOptions {

    private String query;
    private int limit = 100;
    private Instant startTime;
    private Instant endTime;
    private List<String> fields;
    
    /**
     * Create new search options with the specified query.
     * 
     * @param query the search query
     */
    public SearchOptions(String query) {
        this.query = query;
    }
    
    /**
     * Get the search query.
     * 
     * @return the search query
     */
    public String getQuery() {
        return query;
    }
    
    /**
     * Set the search query.
     * 
     * @param query the search query
     * @return this options instance for chaining
     */
    public SearchOptions setQuery(String query) {
        this.query = query;
        return this;
    }
    
    /**
     * Get the maximum number of results to return.
     * 
     * @return the maximum number of results
     */
    public int getLimit() {
        return limit;
    }
    
    /**
     * Set the maximum number of results to return.
     * 
     * @param limit the maximum number of results
     * @return this options instance for chaining
     */
    public SearchOptions setLimit(int limit) {
        this.limit = limit;
        return this;
    }
    
    /**
     * Get the start time for the search range.
     * 
     * @return the start time
     */
    public Instant getStartTime() {
        return startTime;
    }
    
    /**
     * Set the start time for the search range.
     * 
     * @param startTime the start time
     * @return this options instance for chaining
     */
    public SearchOptions setStartTime(Instant startTime) {
        this.startTime = startTime;
        return this;
    }
    
    /**
     * Get the end time for the search range.
     * 
     * @return the end time
     */
    public Instant getEndTime() {
        return endTime;
    }
    
    /**
     * Set the end time for the search range.
     * 
     * @param endTime the end time
     * @return this options instance for chaining
     */
    public SearchOptions setEndTime(Instant endTime) {
        this.endTime = endTime;
        return this;
    }
    
    /**
     * Get the fields to search in.
     * 
     * @return the fields
     */
    public List<String> getFields() {
        return fields;
    }
    
    /**
     * Set the fields to search in.
     * 
     * @param fields the fields
     * @return this options instance for chaining
     */
    public SearchOptions setFields(List<String> fields) {
        this.fields = fields;
        return this;
    }
}

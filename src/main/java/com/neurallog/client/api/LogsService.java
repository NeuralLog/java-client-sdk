package com.neurallog.client.api;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.neurallog.client.model.LogEntry;
import okhttp3.*;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

/**
 * Service for interacting with the NeuralLog logs service.
 */
public class LogsService {

    private final String baseUrl;
    private final OkHttpClient httpClient;
    private final ObjectMapper objectMapper;
    
    /**
     * Create a new logs service with the specified base URL and object mapper.
     * 
     * @param baseUrl the base URL of the logs service
     * @param objectMapper the object mapper for JSON serialization/deserialization
     */
    public LogsService(String baseUrl, ObjectMapper objectMapper) {
        this.baseUrl = baseUrl;
        this.objectMapper = objectMapper;
        
        this.httpClient = new OkHttpClient.Builder()
            .connectTimeout(10, TimeUnit.SECONDS)
            .readTimeout(30, TimeUnit.SECONDS)
            .writeTimeout(30, TimeUnit.SECONDS)
            .build();
    }
    
    /**
     * Append a log entry to the specified log.
     * 
     * @param logName the log name
     * @param logEntry the log entry
     * @param resourceToken the resource token
     * @return the log ID
     * @throws IOException if the request fails
     */
    public String appendLog(String logName, LogEntry logEntry, String resourceToken) throws IOException {
        HttpUrl url = HttpUrl.parse(baseUrl + "/logs/" + logName);
        
        List<LogEntry> entries = new ArrayList<>();
        entries.add(logEntry);
        
        RequestBody body = RequestBody.create(
            objectMapper.writeValueAsString(entries),
            MediaType.parse("application/json")
        );
        
        Request request = new Request.Builder()
            .url(url)
            .header("Authorization", "Bearer " + resourceToken)
            .post(body)
            .build();
        
        try (Response response = httpClient.newCall(request).execute()) {
            if (!response.isSuccessful()) {
                throw new IOException("Failed to append log: " + response.code());
            }
            
            String responseBody = response.body().string();
            Map<String, Object> responseMap = objectMapper.readValue(responseBody, Map.class);
            
            return (String) responseMap.get("logId");
        }
    }
    
    /**
     * Get logs from the specified log.
     * 
     * @param logName the log name
     * @param limit the maximum number of logs to return
     * @param resourceToken the resource token
     * @return the logs
     * @throws IOException if the request fails
     */
    public List<LogEntry> getLogs(String logName, int limit, String resourceToken) throws IOException {
        HttpUrl url = HttpUrl.parse(baseUrl + "/logs/" + logName)
            .newBuilder()
            .addQueryParameter("limit", String.valueOf(limit))
            .build();
        
        Request request = new Request.Builder()
            .url(url)
            .header("Authorization", "Bearer " + resourceToken)
            .get()
            .build();
        
        try (Response response = httpClient.newCall(request).execute()) {
            if (!response.isSuccessful()) {
                throw new IOException("Failed to get logs: " + response.code());
            }
            
            String responseBody = response.body().string();
            Map<String, Object> responseMap = objectMapper.readValue(responseBody, Map.class);
            
            List<Map<String, Object>> entriesMap = (List<Map<String, Object>>) responseMap.get("entries");
            List<LogEntry> entries = new ArrayList<>();
            
            for (Map<String, Object> entryMap : entriesMap) {
                LogEntry entry = new LogEntry();
                entry.setId((String) entryMap.get("id"));
                entry.setTimestamp(java.time.Instant.parse((String) entryMap.get("timestamp")));
                entry.setData((Map<String, Object>) entryMap.get("data"));
                entry.setEncrypted((boolean) entryMap.getOrDefault("encrypted", false));
                entries.add(entry);
            }
            
            return entries;
        }
    }
    
    /**
     * Search logs in the specified log.
     * 
     * @param logName the log name
     * @param searchTokens the search tokens
     * @param limit the maximum number of results to return
     * @param resourceToken the resource token
     * @return the search results
     * @throws IOException if the request fails
     */
    public List<LogEntry> searchLogs(String logName, List<String> searchTokens, int limit, String resourceToken) throws IOException {
        HttpUrl.Builder urlBuilder = HttpUrl.parse(baseUrl + "/search")
            .newBuilder()
            .addQueryParameter("log_name", logName)
            .addQueryParameter("limit", String.valueOf(limit));
        
        for (String token : searchTokens) {
            urlBuilder.addQueryParameter("token", token);
        }
        
        Request request = new Request.Builder()
            .url(urlBuilder.build())
            .header("Authorization", "Bearer " + resourceToken)
            .get()
            .build();
        
        try (Response response = httpClient.newCall(request).execute()) {
            if (!response.isSuccessful()) {
                throw new IOException("Failed to search logs: " + response.code());
            }
            
            String responseBody = response.body().string();
            Map<String, Object> responseMap = objectMapper.readValue(responseBody, Map.class);
            
            List<Map<String, Object>> resultsMap = (List<Map<String, Object>>) responseMap.get("results");
            List<LogEntry> results = new ArrayList<>();
            
            for (Map<String, Object> resultMap : resultsMap) {
                LogEntry entry = new LogEntry();
                Map<String, Object> entryMap = (Map<String, Object>) resultMap.get("entry");
                entry.setId((String) entryMap.get("id"));
                entry.setTimestamp(java.time.Instant.parse((String) entryMap.get("timestamp")));
                entry.setData((Map<String, Object>) entryMap.get("data"));
                entry.setEncrypted((boolean) entryMap.getOrDefault("encrypted", false));
                results.add(entry);
            }
            
            return results;
        }
    }
    
    /**
     * Get all log names.
     * 
     * @param resourceToken the resource token
     * @return the log names
     * @throws IOException if the request fails
     */
    public List<String> getLogNames(String resourceToken) throws IOException {
        HttpUrl url = HttpUrl.parse(baseUrl + "/logs");
        
        Request request = new Request.Builder()
            .url(url)
            .header("Authorization", "Bearer " + resourceToken)
            .get()
            .build();
        
        try (Response response = httpClient.newCall(request).execute()) {
            if (!response.isSuccessful()) {
                throw new IOException("Failed to get log names: " + response.code());
            }
            
            String responseBody = response.body().string();
            Map<String, Object> responseMap = objectMapper.readValue(responseBody, Map.class);
            
            return (List<String>) responseMap.get("logs");
        }
    }
    
    /**
     * Clear a log.
     * 
     * @param logName the log name
     * @param resourceToken the resource token
     * @throws IOException if the request fails
     */
    public void clearLog(String logName, String resourceToken) throws IOException {
        HttpUrl url = HttpUrl.parse(baseUrl + "/logs/" + logName + "/clear");
        
        Request request = new Request.Builder()
            .url(url)
            .header("Authorization", "Bearer " + resourceToken)
            .post(RequestBody.create("", MediaType.parse("application/json")))
            .build();
        
        try (Response response = httpClient.newCall(request).execute()) {
            if (!response.isSuccessful()) {
                throw new IOException("Failed to clear log: " + response.code());
            }
        }
    }
    
    /**
     * Delete a log.
     * 
     * @param logName the log name
     * @param resourceToken the resource token
     * @throws IOException if the request fails
     */
    public void deleteLog(String logName, String resourceToken) throws IOException {
        HttpUrl url = HttpUrl.parse(baseUrl + "/logs/" + logName);
        
        Request request = new Request.Builder()
            .url(url)
            .header("Authorization", "Bearer " + resourceToken)
            .delete()
            .build();
        
        try (Response response = httpClient.newCall(request).execute()) {
            if (!response.isSuccessful()) {
                throw new IOException("Failed to delete log: " + response.code());
            }
        }
    }
}

package com.neurallog.client;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.neurallog.client.api.AuthService;
import com.neurallog.client.api.LogsService;
import com.neurallog.client.crypto.CryptoService;
import com.neurallog.client.crypto.KeyHierarchy;
import com.neurallog.client.exception.AuthenticationException;
import com.neurallog.client.exception.LogException;
import com.neurallog.client.model.EncryptedKEK;
import com.neurallog.client.model.LogEntry;
import com.neurallog.client.model.LoginResponse;
import com.neurallog.client.model.SearchOptions;
import com.neurallog.client.registry.RegistryService;
import com.neurallog.client.registry.TenantEndpoints;

import java.io.IOException;
import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Main client for interacting with the NeuralLog service.
 *
 * This client provides methods for logging, searching, and retrieving logs
 * with zero-knowledge encryption.
 */
public class NeuralLogClient {

    private final String tenantId;
    private String authUrl;
    private String logsUrl;
    private String webUrl;
    private String registryUrl;
    private final ExecutorService executor;
    private final ObjectMapper objectMapper;

    private AuthService authService;
    private LogsService logsService;
    private CryptoService cryptoService;
    private KeyHierarchy keyHierarchy;
    private RegistryService registryService;

    private String apiKey;
    private String masterSecret;
    private boolean authenticated = false;
    private boolean endpointsInitialized = false;

    /**
     * Create a new NeuralLogClient with the specified configuration.
     *
     * @param config the client configuration
     */
    public NeuralLogClient(NeuralLogClientConfig config) {
        this.tenantId = config.getTenantId();
        this.authUrl = config.getAuthUrl();
        this.logsUrl = config.getLogsUrl();
        this.webUrl = config.getWebUrl();
        this.registryUrl = config.getRegistryUrl();
        this.executor = Executors.newCachedThreadPool();

        this.objectMapper = new ObjectMapper();
        this.objectMapper.registerModule(new JavaTimeModule());

        this.authService = new AuthService(authUrl, objectMapper);
        this.logsService = new LogsService(logsUrl, objectMapper);
        this.cryptoService = new CryptoService();
        this.keyHierarchy = new KeyHierarchy();

        if (this.registryUrl != null) {
            this.registryService = new RegistryService(registryUrl, objectMapper);
        }
    }

    /**
     * Initialize the client by fetching endpoints from the registry if needed.
     *
     * @throws IOException if initialization fails
     */
    public void initialize() throws IOException {
        if (endpointsInitialized) {
            return;
        }

        // If all URLs are already provided and registryUrl is not set, skip registry lookup
        if (registryUrl == null && authUrl != null && logsUrl != null) {
            System.out.println("Using provided endpoints");
            endpointsInitialized = true;
            return;
        }

        try {
            // If no registry URL is provided, construct a default one
            if (registryUrl == null) {
                registryUrl = "https://registry." + tenantId + ".neurallog.app";
                System.out.println("Using default registry URL: " + registryUrl);
                registryService = new RegistryService(registryUrl, objectMapper);
            }

            // Fetch tenant endpoints from registry
            System.out.println("Fetching endpoints from registry: " + registryUrl);
            TenantEndpoints endpoints = registryService.getEndpoints();

            // Update services with endpoints
            authUrl = endpoints.getAuthUrl();
            logsUrl = endpoints.getServerUrl();
            webUrl = endpoints.getWebUrl();

            // Update service URLs
            authService = new AuthService(authUrl, objectMapper);
            logsService = new LogsService(logsUrl, objectMapper);

            System.out.println("Endpoints initialized: " +
                "authUrl=" + authUrl + ", " +
                "serverUrl=" + logsUrl + ", " +
                "webUrl=" + webUrl + ", " +
                "apiVersion=" + endpoints.getApiVersion());

            endpointsInitialized = true;
        } catch (Exception e) {
            System.err.println("Failed to initialize client: " + e.getMessage());
            throw new IOException("Failed to initialize client: " + e.getMessage(), e);
        }
    }

    /**
     * Authenticate with an API key.
     *
     * @param apiKey the API key
     * @return true if authentication was successful
     * @throws AuthenticationException if authentication fails
     */
    public boolean authenticateWithApiKey(String apiKey) throws AuthenticationException {
        try {
            // Ensure endpoints are initialized
            initialize();

            // Generate zero-knowledge proof for API key
            String proof = cryptoService.generateApiKeyProof(apiKey);

            boolean valid = authService.validateApiKey(apiKey, tenantId, proof);
            if (valid) {
                this.apiKey = apiKey;
                this.authenticated = true;

                // Initialize key hierarchy from API key
                keyHierarchy.initializeFromApiKey(apiKey, tenantId);

                return true;
            }
            return false;
        } catch (IOException e) {
            throw new AuthenticationException("Failed to authenticate with API key", e);
        } catch (Exception e) {
            throw new AuthenticationException("Failed to process cryptographic operations", e);
        }
    }

    /**
     * Authenticate with username and password.
     *
     * @param username the username
     * @param password the password
     * @return true if authentication was successful
     * @throws AuthenticationException if authentication fails
     */
    public boolean authenticateWithPassword(String username, String password) throws AuthenticationException {
        try {
            // Ensure endpoints are initialized
            initialize();

            // Login with username and password
            LoginResponse loginResponse = authService.login(username, password, tenantId);

            // Set API key from login response
            this.apiKey = loginResponse.getToken();
            this.authenticated = true;

            // Derive master secret
            this.masterSecret = cryptoService.deriveMasterSecret(username, password);

            // Check if there's an existing KEK
            EncryptedKEK encryptedKEK = null;
            try {
                encryptedKEK = authService.getEncryptedKEK(this.apiKey);
            } catch (Exception e) {
                // Ignore errors, we'll create a new KEK if needed
            }

            if (encryptedKEK != null) {
                // Decrypt KEK with master secret
                byte[] kek = cryptoService.decryptKEK(encryptedKEK, this.masterSecret);
                keyHierarchy = new KeyHierarchy(kek);
            } else {
                // Generate new KEK
                byte[] kek = cryptoService.generateKEK();
                keyHierarchy = new KeyHierarchy(kek);

                // Encrypt KEK with master secret
                EncryptedKEK newEncryptedKEK = cryptoService.encryptKEK(kek, this.masterSecret);

                // Store encrypted KEK
                authService.createEncryptedKEK(newEncryptedKEK, this.apiKey);
            }

            return true;
        } catch (IOException e) {
            throw new AuthenticationException("Failed to authenticate with username and password", e);
        } catch (Exception e) {
            throw new AuthenticationException("Failed to process cryptographic operations", e);
        }
    }

    /**
     * Check if the client is authenticated.
     *
     * @return true if the client is authenticated
     */
    public boolean isAuthenticated() {
        return authenticated;
    }

    /**
     * Log data to the specified log.
     *
     * @param logName the log name
     * @param data the data to log
     * @return the log ID
     * @throws LogException if logging fails
     */
    public String log(String logName, Map<String, Object> data) throws LogException {
        if (!authenticated) {
            throw new LogException("Not authenticated");
        }

        try {
            // Ensure endpoints are initialized
            initialize();

            // Encrypt log name
            String encryptedLogName = encryptLogName(logName);

            // Encrypt data
            byte[] encryptionKey = keyHierarchy.deriveLogEncryptionKey(apiKey, tenantId, logName);
            Map<String, Object> encryptedData = cryptoService.encryptLogData(data, encryptionKey);

            // Create log entry
            LogEntry logEntry = new LogEntry();
            logEntry.setId(UUID.randomUUID().toString());
            logEntry.setTimestamp(Instant.now());
            logEntry.setData(encryptedData);
            logEntry.setEncrypted(true);

            // Get resource token
            String resourceToken = authService.getResourceToken(apiKey, tenantId, "logs/" + encryptedLogName);

            // Send log to server
            return logsService.appendLog(encryptedLogName, logEntry, resourceToken);
        } catch (Exception e) {
            throw new LogException("Failed to log data", e);
        }
    }

    /**
     * Get logs from the specified log.
     *
     * @param logName the log name
     * @param limit the maximum number of logs to return
     * @return the logs
     * @throws LogException if retrieving logs fails
     */
    public List<Map<String, Object>> getLogs(String logName, int limit) throws LogException {
        if (!authenticated) {
            throw new LogException("Not authenticated");
        }

        try {
            // Ensure endpoints are initialized
            initialize();

            // Encrypt log name
            String encryptedLogName = encryptLogName(logName);

            // Get resource token
            String resourceToken = authService.getResourceToken(apiKey, tenantId, "logs/" + encryptedLogName);

            // Get logs from server
            List<LogEntry> encryptedLogs = logsService.getLogs(encryptedLogName, limit, resourceToken);

            // Decrypt logs
            byte[] encryptionKey = keyHierarchy.deriveLogEncryptionKey(apiKey, tenantId, logName);
            return encryptedLogs.stream()
                .map(logEntry -> {
                    try {
                        return cryptoService.decryptLogData(logEntry.getData(), encryptionKey);
                    } catch (Exception e) {
                        throw new RuntimeException("Failed to decrypt log data", e);
                    }
                })
                .toList();
        } catch (Exception e) {
            throw new LogException("Failed to get logs", e);
        }
    }

    /**
     * Search logs in the specified log.
     *
     * @param logName the log name
     * @param options the search options
     * @return the search results
     * @throws LogException if searching logs fails
     */
    public List<Map<String, Object>> searchLogs(String logName, SearchOptions options) throws LogException {
        if (!authenticated) {
            throw new LogException("Not authenticated");
        }

        try {
            // Ensure endpoints are initialized
            initialize();

            // Encrypt log name
            String encryptedLogName = encryptLogName(logName);

            // Get resource token
            String resourceToken = authService.getResourceToken(apiKey, tenantId, "logs/" + encryptedLogName);

            // Generate search tokens
            byte[] searchKey = keyHierarchy.deriveLogSearchKey(apiKey, tenantId, logName);
            List<String> searchTokens = cryptoService.generateSearchTokens(options.getQuery(), searchKey);

            // Search logs on server
            List<LogEntry> encryptedResults = logsService.searchLogs(encryptedLogName, searchTokens, options.getLimit(), resourceToken);

            // Decrypt results
            byte[] encryptionKey = keyHierarchy.deriveLogEncryptionKey(apiKey, tenantId, logName);
            return encryptedResults.stream()
                .map(logEntry -> {
                    try {
                        return cryptoService.decryptLogData(logEntry.getData(), encryptionKey);
                    } catch (Exception e) {
                        throw new RuntimeException("Failed to decrypt log data", e);
                    }
                })
                .toList();
        } catch (Exception e) {
            throw new LogException("Failed to search logs", e);
        }
    }

    /**
     * Get all log names.
     *
     * @return the log names
     * @throws LogException if retrieving log names fails
     */
    public List<String> getLogNames() throws LogException {
        if (!authenticated) {
            throw new LogException("Not authenticated");
        }

        try {
            // Ensure endpoints are initialized
            initialize();

            // Get resource token
            String resourceToken = authService.getResourceToken(apiKey, tenantId, "logs");

            // Get encrypted log names from server
            List<String> encryptedLogNames = logsService.getLogNames(resourceToken);

            // Decrypt log names
            return encryptedLogNames.stream()
                .map(encryptedLogName -> {
                    try {
                        return decryptLogName(encryptedLogName);
                    } catch (Exception e) {
                        throw new RuntimeException("Failed to decrypt log name", e);
                    }
                })
                .toList();
        } catch (Exception e) {
            throw new LogException("Failed to get log names", e);
        }
    }

    /**
     * Clear a log.
     *
     * @param logName the log name
     * @throws LogException if clearing the log fails
     */
    public void clearLog(String logName) throws LogException {
        if (!authenticated) {
            throw new LogException("Not authenticated");
        }

        try {
            // Ensure endpoints are initialized
            initialize();

            // Encrypt log name
            String encryptedLogName = encryptLogName(logName);

            // Get resource token
            String resourceToken = authService.getResourceToken(apiKey, tenantId, "logs/" + encryptedLogName);

            // Clear log on server
            logsService.clearLog(encryptedLogName, resourceToken);
        } catch (Exception e) {
            throw new LogException("Failed to clear log", e);
        }
    }

    /**
     * Delete a log.
     *
     * @param logName the log name
     * @throws LogException if deleting the log fails
     */
    public void deleteLog(String logName) throws LogException {
        if (!authenticated) {
            throw new LogException("Not authenticated");
        }

        try {
            // Ensure endpoints are initialized
            initialize();

            // Encrypt log name
            String encryptedLogName = encryptLogName(logName);

            // Get resource token
            String resourceToken = authService.getResourceToken(apiKey, tenantId, "logs/" + encryptedLogName);

            // Delete log on server
            logsService.deleteLog(encryptedLogName, resourceToken);
        } catch (Exception e) {
            throw new LogException("Failed to delete log", e);
        }
    }

    /**
     * Log data asynchronously.
     *
     * @param logName the log name
     * @param data the data to log
     * @return a CompletableFuture that completes with the log ID
     */
    public CompletableFuture<String> logAsync(String logName, Map<String, Object> data) {
        return CompletableFuture.supplyAsync(() -> {
            try {
                return log(logName, data);
            } catch (LogException e) {
                throw new RuntimeException(e);
            }
        }, executor);
    }

    /**
     * Encrypt a log name.
     *
     * @param logName the log name
     * @return the encrypted log name
     * @throws Exception if encryption fails
     */
    private String encryptLogName(String logName) throws Exception {
        byte[] logNameKey = keyHierarchy.deriveLogNameKey(apiKey, tenantId);
        return cryptoService.encryptLogName(logName, logNameKey);
    }

    /**
     * Decrypt a log name.
     *
     * @param encryptedLogName the encrypted log name
     * @return the decrypted log name
     * @throws Exception if decryption fails
     */
    private String decryptLogName(String encryptedLogName) throws Exception {
        byte[] logNameKey = keyHierarchy.deriveLogNameKey(apiKey, tenantId);
        return cryptoService.decryptLogName(encryptedLogName, logNameKey);
    }

    /**
     * Close the client and release resources.
     */
    public void close() {
        executor.shutdown();
    }
}

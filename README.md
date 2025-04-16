# NeuralLog Java Client SDK

A zero-knowledge Java client SDK for the NeuralLog system, designed to provide secure, end-to-end encrypted logging capabilities for Java applications.

## Features

- **Zero-Knowledge Architecture**: All encryption/decryption happens client-side
- **Secure Logging**: End-to-end encrypted logs
- **Encrypted Log Names**: Log names are encrypted before being sent to the server
- **API Key Management**: Create and manage API keys
- **Searchable Encryption**: Search encrypted logs without compromising security
- **Auth Service Integration**: Seamless integration with the NeuralLog auth service
- **Resource Token Management**: Secure access to logs using short-lived resource tokens
- **Cross-Platform**: Compatible with all Java platforms
- **Java 22 Support**: Built for modern Java applications

## Installation

```xml
<dependency>
    <groupId>com.neurallog</groupId>
    <artifactId>neurallog-client-sdk</artifactId>
    <version>0.1.0-SNAPSHOT</version>
</dependency>
```

## Usage

### Basic Usage

```java
import com.neurallog.client.NeuralLogClient;
import com.neurallog.client.NeuralLogClientConfig;
import com.neurallog.client.exception.LogException;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class Example {
    public static void main(String[] args) {
        // Create client configuration
        NeuralLogClientConfig config = new NeuralLogClientConfig()
            .setTenantId("your-tenant-id")
            .setAuthUrl("https://auth.neurallog.com")
            .setLogsUrl("https://logs.neurallog.com");

        // Create client
        NeuralLogClient client = new NeuralLogClient(config);

        // Authenticate with API key
        try {
            client.authenticateWithApiKey("your-api-key");

            // Log data
            Map<String, Object> logData = new HashMap<>();
            logData.put("level", "info");
            logData.put("message", "Hello, NeuralLog!");
            logData.put("timestamp", java.time.Instant.now().toString());
            logData.put("user", "john.doe");
            logData.put("action", "login");

            String logId = client.log("application-logs", logData);
            System.out.println("Log sent with ID: " + logId);

            // Get logs
            List<Map<String, Object>> logs = client.getLogs("application-logs", 10);
            System.out.println("Recent logs: " + logs);

            // Search logs
            SearchOptions searchOptions = new SearchOptions("login")
                .setLimit(10);
            List<Map<String, Object>> searchResults = client.searchLogs("application-logs", searchOptions);
            System.out.println("Search results: " + searchResults);

        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            // Close client
            client.close();
        }
    }
}
```

### Asynchronous Logging

```java
import com.neurallog.client.NeuralLogClient;
import com.neurallog.client.NeuralLogClientConfig;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

public class AsyncExample {
    public static void main(String[] args) {
        // Create client
        NeuralLogClient client = new NeuralLogClient(
            new NeuralLogClientConfig("your-tenant-id")
        );

        // Authenticate
        client.authenticateWithApiKey("your-api-key");

        // Log data asynchronously
        Map<String, Object> logData = new HashMap<>();
        logData.put("level", "info");
        logData.put("message", "Async logging example");

        CompletableFuture<String> future = client.logAsync("application-logs", logData);

        future.thenAccept(logId -> {
            System.out.println("Log sent with ID: " + logId);
        }).exceptionally(e -> {
            System.err.println("Failed to send log: " + e.getMessage());
            return null;
        });

        // ... do other work ...

        // Close client when done
        client.close();
    }
}
```

## Security

The NeuralLog Client SDK is designed with security in mind:

- All encryption/decryption happens client-side
- The server never sees plaintext data or log names
- API keys are used to derive encryption keys
- Searchable encryption allows searching without compromising security

### Key Hierarchy

The SDK uses a hierarchical key derivation system:

```
API Key
   |
   ├── Log Encryption Key (per log)
   |
   ├── Log Search Key (per log)
   |
   └── Log Name Key
```

## Documentation

Detailed documentation is available in the [docs](./docs) directory:

- [API Reference](./docs/api.md)
- [Configuration](./docs/configuration.md)
- [Architecture](./docs/architecture.md)
- [Examples](./docs/examples)

For integration guides and tutorials, visit the [NeuralLog Documentation Site](https://neurallog.github.io/docs/).

## Contributing

Contributions are welcome! Please read our [Contributing Guide](./CONTRIBUTING.md) for details on our code of conduct and the process for submitting pull requests.

## Related NeuralLog Components

- [NeuralLog Auth](https://github.com/NeuralLog/auth) - Authentication and authorization
- [NeuralLog Server](https://github.com/NeuralLog/server) - Core server functionality
- [NeuralLog Web](https://github.com/NeuralLog/web) - Web interface components
- [NeuralLog TypeScript Client SDK](https://github.com/NeuralLog/typescript-client-sdk) - TypeScript client SDK

## License

MIT

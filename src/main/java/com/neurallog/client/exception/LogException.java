package com.neurallog.client.exception;

/**
 * Exception thrown when a log operation fails.
 */
public class LogException extends Exception {

    /**
     * Create a new log exception with the specified message.
     * 
     * @param message the exception message
     */
    public LogException(String message) {
        super(message);
    }
    
    /**
     * Create a new log exception with the specified message and cause.
     * 
     * @param message the exception message
     * @param cause the exception cause
     */
    public LogException(String message, Throwable cause) {
        super(message, cause);
    }
}

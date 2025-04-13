package com.neurallog.client.exception;

/**
 * Exception thrown when authentication fails.
 */
public class AuthenticationException extends Exception {

    /**
     * Create a new authentication exception with the specified message.
     * 
     * @param message the exception message
     */
    public AuthenticationException(String message) {
        super(message);
    }
    
    /**
     * Create a new authentication exception with the specified message and cause.
     * 
     * @param message the exception message
     * @param cause the exception cause
     */
    public AuthenticationException(String message, Throwable cause) {
        super(message, cause);
    }
}

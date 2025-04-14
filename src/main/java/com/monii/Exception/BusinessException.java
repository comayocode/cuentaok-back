package com.monii.Exception;

import lombok.Getter;

@Getter
public class BusinessException extends RuntimeException {
    private final int statusCode;
    private Object additionalData;

    public BusinessException(String message, int statusCode) {
        super(message);
        this.statusCode = statusCode;
    }

    public BusinessException(String message, int statusCode, Object additionalData) {
        super(message);
        this.statusCode = statusCode;
        this.additionalData = additionalData;
    }

}

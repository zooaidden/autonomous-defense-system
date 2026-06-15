package com.autonomous.defense.actuator.common;

import lombok.Builder;

import java.time.Instant;

@Builder
public record ApiResponse<T>(
        boolean success,
        String code,
        String message,
        T data,
        Instant timestamp
) {
    public static <T> ApiResponse<T> ok(T data) {
        return ApiResponse.<T>builder()
                .success(true)
                .code("OK")
                .message("success")
                .data(data)
                .timestamp(Instant.now())
                .build();
    }
}


package com.cuentaok.dto;

import lombok.Getter;

@Getter
public class VerifyAccount {
    private String token;

    public void setToken(String token) {
        this.token = token;
    }
}

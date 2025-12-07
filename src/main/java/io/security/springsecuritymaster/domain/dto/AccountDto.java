package io.security.springsecuritymaster.domain.dto;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class AccountDto {
    private String id;
    private String username;
    private String password;
    private int age;
    private String roles;
}

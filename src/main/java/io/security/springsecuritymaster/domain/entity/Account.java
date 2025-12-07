package io.security.springsecuritymaster.domain.entity;

import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.Id;
import lombok.Data;

@Data
@Entity
public class Account {
    @Id
    @GeneratedValue
    private Long id;

    private String username;
    private String password;
    private int age;
    private String roles;
}

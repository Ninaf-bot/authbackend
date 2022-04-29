package com.authenticationtest.authbackend.Entity;

import lombok.*;

import javax.persistence.*;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Builder
public class User {
    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    Integer UserID;
    @Column(nullable = false, unique = true)
    String username;
    String password;

}

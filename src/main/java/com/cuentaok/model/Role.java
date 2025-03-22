package com.cuentaok.model;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import java.util.Set;

@Entity
@Table(name = "roles")
@Getter
@Setter
@NoArgsConstructor
public class Role {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Enumerated(EnumType.STRING) // Guarda el enum como String en la BD
    @Column(unique = true, nullable = false)
    private RoleName name;

    public Role(RoleName name) {
        this.name = name;
    }
}


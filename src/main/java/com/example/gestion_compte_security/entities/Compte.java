package com.example.gestion_compte_security.entities;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Entity
public class Compte {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)

    private Long id;

    @Column(name = "nom", length=100)
    private String nom;
    @Column(name = "tel", length=100)
    private String tel;
    @Column(name = "montant", length=100)
    private Double montant;
}
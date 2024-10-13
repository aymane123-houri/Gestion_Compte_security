package com.example.gestion_compte_security.Repository;

import com.example.gestion_compte_security.entities.Compte;
import org.springframework.data.jpa.repository.JpaRepository;

public interface CompteRepository extends JpaRepository<Compte,Long> {
}

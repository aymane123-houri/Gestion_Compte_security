package com.example.gestion_compte_security.service;


import com.example.gestion_compte_security.Repository.CompteRepository;
import com.example.gestion_compte_security.entities.Compte;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class CompteService {

    @Autowired
    private CompteRepository compteRepositoty;

    public Compte CreateCompte(Compte compte){
        return compteRepositoty.save(compte);
    }

    public List<Compte> GetAllCompte(){
        return compteRepositoty.findAll();
    }

    public Compte GetCompteById(Long id){
        return compteRepositoty.findById(id).orElse(null);
    }

    public void DeleteCompte(Long id){
        compteRepositoty.deleteById(id);
    }

    public Compte UpdateCompte(Long id, Compte New){

        return compteRepositoty.findById(id).map(compte -> {
            compte.setNom(New.getNom());
            compte.setTel(New.getTel());
            compte.setMontant(New.getMontant());
            return  compteRepositoty.save(compte);
        }).orElseThrow(() -> new RuntimeException("non trouvé"));

    }

    public Compte Crediter(Long id, float m){
        return compteRepositoty.findById(id).map(compte -> {
            compte.setMontant(compte.getMontant()+m);
            return  compteRepositoty.save(compte);
        }).orElseThrow(() -> new RuntimeException("non trouvé"));

    }

    public Compte Debiter(Long id, float m){
        Compte compte = compteRepositoty.findById(id)
                .orElseThrow(() -> new RuntimeException("Compte non trouvé avec l'ID : " + id));

        if (compte.getMontant()>= m){
            compte.setMontant(compte.getMontant()-m);
        }
        return compteRepositoty.save(compte);
    }




}
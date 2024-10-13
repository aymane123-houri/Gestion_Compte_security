package com.example.gestion_compte_security;

import java.io.FileWriter;
import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;

public class RSAKeyPairToFile {

    public static void main(String[] args) {
        try {
            // 1. Initialisation du générateur de paires de clés RSA
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048); // Taille de clé RSA, ici 2048 bits

            // 2. Génération de la paire de clés
            KeyPair keyPair = keyPairGenerator.generateKeyPair();

            // 3. Récupération des clés publique et privée
            PublicKey publicKey = keyPair.getPublic();
            PrivateKey privateKey = keyPair.getPrivate();

            // 4. Encodage des clés en Base64 pour les enregistrer sous format texte lisible (PEM)
            String publicKeyPEM = "-----BEGIN PUBLIC KEY-----\n" +
                    Base64.getMimeEncoder(64, new byte[] {'\n'}).encodeToString(publicKey.getEncoded()) +
                    "\n-----END PUBLIC KEY-----\n";

            String privateKeyPEM = "-----BEGIN PRIVATE KEY-----\n" +
                    Base64.getMimeEncoder(64, new byte[] {'\n'}).encodeToString(privateKey.getEncoded()) +
                    "\n-----END PRIVATE KEY-----\n";

            // 5. Enregistrement des clés dans des fichiers
            writeToFile("C:\\Users\\ultra\\Desktop\\S9\\SOA\\tous_Projet_Prof\\Microservice_TP1\\gestion_compte_security\\src\\main\\resources\\Keys/publicKey.pem", publicKeyPEM);
            writeToFile("C:\\Users\\ultra\\Desktop\\S9\\SOA\\tous_Projet_Prof\\Microservice_TP1\\gestion_compte_security\\src\\main\\resources\\Keys/privateKey.pem", privateKeyPEM);

            System.out.println("Clé publique et privée générées et stockées dans des fichiers.");

        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    // Méthode pour écrire une chaîne de caractères dans un fichier
    public static void writeToFile(String filePath, String content) {
        try (FileWriter writer = new FileWriter(filePath)) {
            writer.write(content);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
package com.example.gestion_compte_security.controller;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

@RestController
public class Oauth2_controller {

    private AuthenticationManager authenticationManager;
    private JwtEncoder jwtEncoder;
    private JwtDecoder jwtDecoder;
    private UserDetailsService userDetailsService;

    public Oauth2_controller(AuthenticationManager authenticationManager, JwtEncoder jwtEncoder, JwtDecoder jwtDecoder, UserDetailsService userDetailsService) {
        this.authenticationManager = authenticationManager;
        this.jwtEncoder = jwtEncoder;
        this.jwtDecoder = jwtDecoder;
        this.userDetailsService = userDetailsService;
    }

    @PostMapping("/login")
    public Map<String, String> login(@RequestParam String username, @RequestParam String password){
        System.out.println("Login attempt with username: " + username);
        // vérifier authetification
        Authentication authenticate = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(username, password)
        );

        // générer les tokens
        Instant instant = Instant.now();
        // recupérer Scopes de l'utilisateur

       // String scopes =  authenticate.getAuthorities().stream().map(auth -> auth.getAuthority()).collect(Collectors.joining(" "));

        var scopes = authenticate.getAuthorities()
                .stream()
                .map(auth -> auth.getAuthority())
                .collect(Collectors.toList());



        System.out.println("scope: " + scopes);

        JwtClaimsSet jwtClaimsSet_Access_token =  JwtClaimsSet.builder()
                .issuer("MS_sec")
                .subject(authenticate.getName())
                .issuedAt(instant)
                .expiresAt(instant.plus(5, ChronoUnit.MINUTES))
                .claim("name",authenticate.getName())
                .claim("SCOPE",scopes)
                .build();
        // Signée le token
        String Access_Token = jwtEncoder.encode(JwtEncoderParameters.from(jwtClaimsSet_Access_token)).getTokenValue();

        // refresh Token

        JwtClaimsSet jwtClaimsSet_refresh_token =  JwtClaimsSet.builder()
                .issuer("MS_sec")
                .subject(authenticate.getName())
                .issuedAt(instant)
                .expiresAt(instant.plus(15, ChronoUnit.MINUTES))

                .claim("name",authenticate.getName())
                .claim("SCOPE",scopes)
                .build();
        String RefreshToken = jwtEncoder.encode(JwtEncoderParameters.from(jwtClaimsSet_refresh_token)).getTokenValue();

        Map<String, String> ID_Token = new HashMap<>();

        ID_Token.put("Access_Token",Access_Token);
        ID_Token.put("Refresh_Token",RefreshToken);

        return ID_Token;
    }

    @PostMapping("/RefreshToken")
    public  Map<String,String> fr_t(String RefreshToken){

        if(RefreshToken==null){
            return Map.of("Message error","Refresh_Token est necessaite");
        }

        // vérifer la sig
        Jwt decoded = jwtDecoder.decode(RefreshToken);

        String  username = decoded.getSubject();

        UserDetails userDetails = userDetailsService.loadUserByUsername(username);

        // renouveller

        Instant instant = Instant.now();
        // recup Scopes

        String scopes =  userDetails.getAuthorities().stream().map(auth -> auth.getAuthority()).collect(Collectors.joining(" "));

        JwtClaimsSet jwtClaimsSet_Access_token =  JwtClaimsSet.builder()
                .issuer("MS_sec")
                .subject(userDetails.getUsername())
                .issuedAt(instant)
                .expiresAt(instant.plus(2, ChronoUnit.MINUTES))
                .claim("name",userDetails.getUsername())
                .claim("SCOPE",scopes)
                .build();
        String Access_Token = jwtEncoder.encode(JwtEncoderParameters.from(jwtClaimsSet_Access_token)).getTokenValue();

        Map<String, String> ID_Token = new HashMap<>();
        ID_Token.put("Access_Token",Access_Token);
        ID_Token.put("Refresh_Token",RefreshToken);

        return ID_Token;

    }

}


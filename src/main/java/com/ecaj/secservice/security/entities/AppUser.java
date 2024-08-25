package com.ecaj.secservice.security.entities;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import javax.persistence.*;
import java.util.ArrayList;
import java.util.Collection;
@Entity
@Data @NoArgsConstructor @AllArgsConstructor
public class AppUser {
    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    private String username;

    /**
     * Permet de prendre la valeur et la stocker (en ecriture setPassword)
     * Ne permet pas de sérialiser le mot de passe en Json (en lecture getPassword)
     */
    @JsonProperty(access = JsonProperty.Access.WRITE_ONLY)
    private String password;


    /**
     * EAGER Charge un utilisateur avec ses roles et LAZY Charge un utilisateur sans ses roles
     * Quand on utilise EAGER il est preferable d'initialiser la collection avec new ArrayList<>()
     */
    @ManyToMany(fetch = FetchType.EAGER)
    private Collection<AppRole> appRoles = new ArrayList<>();
}

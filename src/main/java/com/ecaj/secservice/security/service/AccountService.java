package com.ecaj.secservice.security.service;

import com.ecaj.secservice.security.entities.AppRole;
import com.ecaj.secservice.security.entities.AppUser;

import java.util.List;

public interface AccountService {

    /**
     * Permet d'ajouter un utilisateur
     * On lui donne un objet de type AppUser et il l'ajoute dans la base de donnees
     * @param appUser
     * @return
     */
    AppUser addNewUser(AppUser appUser);

    /**
     * Permet d'ajouter un role
     * On lui donne un objet de type AppRole et il l'ajoute dans la base de donnees
     * @param appRole
     * @return
     */
    AppRole addNewRole(AppRole appRole);

    /**
     * Permet d'ajouter un role à un utilisateur
     * Pour affecter un role à un utilisateur on lui passe deux parametres, username et roleName
     * @param username
     * @param roleName
     */
    void addRoleToUser(String username, String roleName);

    /**
     * Permet de charger un utilisateur par son username
     * @param username
     * @return
     */
    AppUser loadUserByUsername(String username);

    /**
     * Permet d'Afficher tous les utilisateurs
     * @return
     */
    List<AppUser> usersList();
}

package com.ecaj.secservice.security.service;

import com.ecaj.secservice.security.entities.AppRole;
import com.ecaj.secservice.security.entities.AppUser;
import com.ecaj.secservice.security.repo.AppRoleRepository;
import com.ecaj.secservice.security.repo.AppUserRepository;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
@Service
@Transactional
public class AccountServiceImpl implements AccountService {
    private AppUserRepository appUserRepository;
    private AppRoleRepository appRoleRepository;
    private PasswordEncoder passwordEncoder;

    public AccountServiceImpl(AppUserRepository appUserRepository, AppRoleRepository appRoleRepository, PasswordEncoder passwordEncoder) {
        this.appUserRepository = appUserRepository;
        this.appRoleRepository = appRoleRepository;
        this.passwordEncoder = passwordEncoder;
    }

    /**
     * Ajout d'un utilisateur et encodage du mot de passe
     * Recuperation du mot de passe saisi par l'utilisateur
     * Encodage du mot de passe de l'utilisateur
     * @param appUser
     * @return
     */
    @Override
    public AppUser addNewUser(AppUser appUser) {
        String password = appUser.getPassword();
        appUser.setPassword(passwordEncoder.encode(password));
        return appUserRepository.save(appUser);
    }

    /**
     * Ajout d'un role dans la base de données
     * @param appRole
     * @return
     */
    @Override
    public AppRole addNewRole(AppRole appRole) {
        return appRoleRepository.save(appRole);
    }

    /**
     * Affectation d'un role à un utilisateur
     * Recuperation de l'utilisateur à partir de la base de données
     * Recuperation du role à partir de la base de données
     * Ajout du role dans la collection des roles
     * @param username
     * @param roleName
     */
    @Override
    public void addRoleToUser(String username, String roleName) {
        AppUser appUser = appUserRepository.findByUsername(username);
        AppRole appRole = appRoleRepository.findByRoleName(roleName);
        appUser.getAppRoles().add(appRole);
    }

    /**
     * Chargement d'un utilisateur à partir d'un username
     * @param username
     * @return
     */
    @Override
    public AppUser loadUserByUsername(String username) {
        return appUserRepository.findByUsername(username);
    }

    /**
     * Retournement de la liste de tous les utilisateurs
     * @return
     */
    @Override
    public List<AppUser> usersList() {
        return appUserRepository.findAll();
    }
}

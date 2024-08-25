package com.ecaj.secservice.security.service;

import com.ecaj.secservice.security.entities.AppUser;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.Collection;
@Service
public class UserDetailsServiceImpl implements UserDetailsService {
    private AccountService accountService;

    public UserDetailsServiceImpl(AccountService accountService) {
        this.accountService = accountService;
    }

    /**
     * Spécification des utilisateurs qui ont le droit d'acceder à l'application
     * La spécification qui permet d'indiquer à Spring où il doit chercher l'utilisateur
     * Récupération d'utilisateur à partir de la base de données
     * Retour  d'un objet user de Spring
     * @param username
     * @return
     * @throws UsernameNotFoundException
     */
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        AppUser appUser= accountService.loadUserByUsername(username);
        Collection<GrantedAuthority> authorities=new ArrayList<>();
        appUser.getAppRoles().forEach(role->{
            authorities.add(new SimpleGrantedAuthority(role.getRoleName()));
        });
        return new User(appUser.getUsername(), appUser.getPassword(), authorities);
    }
}

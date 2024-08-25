package com.ecaj.secservice.security.repo;

import com.ecaj.secservice.security.entities.AppUser;
import org.springframework.data.jpa.repository.JpaRepository;

public interface AppUserRepository extends JpaRepository<AppUser, Long> {

    /**
     * Permet de Retourner un utilisateur par son username
     * @param username
     * @return
     */
    AppUser findByUsername(String username);
}

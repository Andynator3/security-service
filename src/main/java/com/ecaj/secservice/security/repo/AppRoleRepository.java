package com.ecaj.secservice.security.repo;

import com.ecaj.secservice.security.entities.AppRole;
import org.springframework.data.jpa.repository.JpaRepository;

public interface AppRoleRepository extends JpaRepository<AppRole, Long> {

    /**
     * Permet de retourner un role avec le nom du role
     * @param RoleName
     * @return
     */
    AppRole findByRoleName(String RoleName);
}

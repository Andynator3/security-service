package com.ecaj.secservice;

import com.ecaj.secservice.security.entities.AppRole;
import com.ecaj.secservice.security.entities.AppUser;
import com.ecaj.secservice.security.service.AccountService;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.ArrayList;

@SpringBootApplication
@EnableGlobalMethodSecurity(prePostEnabled = true, securedEnabled = true)
public class SecServiceApplication {

    public static void main(String[] args) {

        SpringApplication.run(SecServiceApplication.class, args);
    }

    /**
     * Creation de la methode  passwordEncoder qui permet d'encoder le mot de passe
     * L'annotation @Bean permet de placer le password dans le contexte de l'appli
     * @return
     */
    @Bean
    PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

    /**
     * Creation d'un objet CommandLineRunner pour tester l'application
     * Déclaration de l'objet accountService de l'interface AccountService dont se trouvent les méthodes que l'on veut tester
     * Retourne une expression lamda qui va s'executer au demmarage grace à l'annotation @Bean
     * Ajout des roles
     * Ajout des utilisateurs
     * Affectation des roles aux utilisateurs
     * @param accountService
     * @return
     */
    @Bean
    CommandLineRunner start(AccountService accountService){
        return args -> {
            accountService.addNewRole(new AppRole(null, "USER"));
            accountService.addNewRole(new AppRole(null, "ADMIN"));
            accountService.addNewRole(new AppRole(null, "CUSTOMER_MANAGER"));
            accountService.addNewRole(new AppRole(null, "PRODUCT_MANAGER"));
            accountService.addNewRole(new AppRole(null, "BILLS_MANAGER"));

            accountService.addNewUser(new AppUser(null,"user1","1230",new ArrayList<>()));
            accountService.addNewUser(new AppUser(null,"admin","1230",new ArrayList<>()));
            accountService.addNewUser(new AppUser(null,"user2","1230",new ArrayList<>()));
            accountService.addNewUser(new AppUser(null,"user3","1230",new ArrayList<>()));
            accountService.addNewUser(new AppUser(null,"user4","1230",new ArrayList<>()));

            accountService.addRoleToUser("user1","USER");
            accountService.addRoleToUser("admin","USER");
            accountService.addRoleToUser("admin","ADMIN");
            accountService.addRoleToUser("user2","USER");
            accountService.addRoleToUser("user2","CUSTOMER_MANAGER");
            accountService.addRoleToUser("user3","USER");
            accountService.addRoleToUser("user3","PRODUCT_MANAGER");
            accountService.addRoleToUser("user4","USER");
            accountService.addRoleToUser("user4","BILLS_MANAGER");
        };
    }

}

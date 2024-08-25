package com.ecaj.secservice.security.web;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.ecaj.secservice.security.JWTUtils;
import com.ecaj.secservice.security.entities.AppRole;
import com.ecaj.secservice.security.entities.AppUser;
import com.ecaj.secservice.security.service.AccountService;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.Data;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.security.Principal;
import java.util.*;
import java.util.stream.Collectors;

@RestController
public class AccountRestController {
    private AccountService accountService;

    public AccountRestController(AccountService accountService) {
        this.accountService = accountService;
    }

    /**
     * Permet de retourner une liste d'utilisateur
     * /users permet d'acceder à la méthode
     * @return
     */
    @GetMapping(path = "/users")
    @PostAuthorize("hasAuthority('USER')")
    public List<AppUser> appUsers(){
        return accountService.usersList();
    }

    /**
     * Permet d'ajouter un utilisateur dans la base de données
     * @param appUser
     * @return
     */
    @PostMapping(path = "/users")
    @PostAuthorize("hasAuthority('ADMIN')")
    public AppUser saveUser(@RequestBody AppUser appUser){
        return accountService.addNewUser(appUser);
    }

    /**
     * Permet d'ajouter un role dans la base de données
     * @param appRole
     * @return
     */
    @PostMapping(path = "/roles")
    @PostAuthorize("hasAuthority('ADMIN')")
    public AppRole saveRole(@RequestBody AppRole appRole){
        return accountService.addNewRole(appRole);
    }

    /**
     * Permet d'ajouter un role à un utilisateur
     * @param roleUserForm
     */
    @PostMapping(path = "/addNewRoleToUser")
    @PostAuthorize("hasAuthority('ADMIN')")
    public void addNewRoleToUser(@RequestBody RoleUserForm roleUserForm){
       accountService.addRoleToUser(roleUserForm.getUsername(),roleUserForm.getRoleName());
    }

    @GetMapping(path = "/refreshToken")
    public void refreshToken(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String authToken = request.getHeader(JWTUtils.AUTH_HEADER);
        if(authToken != null && authToken.startsWith(JWTUtils.PREFIX)){
            try{
                String jwt = authToken.substring(JWTUtils.PREFIX.length());
                Algorithm algorithm = Algorithm.HMAC256(JWTUtils.SECRET);
                JWTVerifier jwtVerifier = JWT.require(algorithm).build();
                DecodedJWT decodedJWT = jwtVerifier.verify(jwt);
                String username = decodedJWT.getSubject();
                AppUser appUser = accountService.loadUserByUsername(username);
                String jwtAccessToken = JWT.create()
                        .withSubject(appUser.getUsername())
                        .withExpiresAt(new Date(System.currentTimeMillis()+JWTUtils.EXPIRED_ACCESS_TOKEN))
                        .withIssuer(request.getRequestURL().toString())
                        .withClaim("roles",appUser.getAppRoles().stream().map(role->role.getRoleName()).collect(Collectors.toList()))
                        .sign(algorithm);
                Map<String,String> idToken = new HashMap<>();
                idToken.put("accessToken",jwtAccessToken);
                idToken.put("refreshToken",jwt);
                response.setContentType("application/json");
                new ObjectMapper().writeValue(response.getOutputStream(),idToken);
            }
            catch (Exception e){
               throw e;
            }
        }
        else{
            throw new RuntimeException("Refresh Token requied!!");
        }
    }

    /**
     * Méthode qui permet de consulter le profile de l'utilisateur authentifié
     * @param principal
     * @return
     */
    @GetMapping("/profile")
    public AppUser profile(Principal principal){
        return accountService.loadUserByUsername(principal.getName());
    }

}
@Data
class RoleUserForm {
    private String username;
    private String roleName;
}

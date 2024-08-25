package com.ecaj.secservice.security.filters;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.ecaj.secservice.security.JWTUtils;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
    private AuthenticationManager authenticationManager;

    public JwtAuthenticationFilter(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }

    /**
     * Récupération du username et du password en utilisant l'objet request, ils sont envoyés en format 3wFormUrlEncoded
     * Stockage du username et du password dans un objet Spring de type UsernamePasswordAuthenticationToken en les mettant en paramètre
     * @param request
     * @param response
     * @return Retour à Spring l'objet authenticationToken pour authentifier l'utilisateur
     * @throws AuthenticationException
     */
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        System.out.println("attemptAuthentication");
        String username = request.getParameter("username");
        String password = request.getParameter("password");
        System.out.println(username);
        System.out.println(password);
        UsernamePasswordAuthenticationToken authenticationToken =
                new UsernamePasswordAuthenticationToken(username, password);
        return authenticationManager.authenticate(authenticationToken);
    }

    /**
     * Obtention de l'utilisateur authentifié avec l'objet authResult et stockage dans l'objet user
     * Génération du JWT et Installation d'une librairie qui permet de le générer auth0 jwt maven
     * Conversion d'une liste de role de type Authorities en une liste de string
     * Signature du token avec l'algorithm HMAC256
     * Création de accessToken
     * Envoi du jwt au client dans un header
     * Création de accessToken et de refreshToken
     * Envoi du jwt en format json dans le corps de la requete
     * @param request
     * @param response
     * @param chain
     * @param authResult le resultat de l'authentification qui contient username et ses roles
     * @throws IOException
     * @throws ServletException
     */
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        System.out.println("successfulAuthentication");
        User user = (User) authResult.getPrincipal();
        Algorithm algorithm1 = Algorithm.HMAC256(JWTUtils.SECRET);
        String jwtAccessToken = JWT.create()
                .withSubject(user.getUsername())
                .withExpiresAt(new Date(System.currentTimeMillis()+JWTUtils.EXPIRED_ACCESS_TOKEN))
                .withIssuer(request.getRequestURL().toString())
                .withClaim("roles",user.getAuthorities().stream().map(ga->ga.getAuthority()).collect(Collectors.toList()))
                .sign(algorithm1);

        String jwtRefreshToken = JWT.create()
                .withSubject(user.getUsername())
                .withExpiresAt(new Date(System.currentTimeMillis()+JWTUtils.EXPIRED_REFRESH_TOKEN))
                .withIssuer(request.getRequestURL().toString())
                .sign(algorithm1);
        Map<String,String> idToken = new HashMap<>();
        idToken.put("accessToken",jwtAccessToken);
        idToken.put("refreshToken",jwtRefreshToken);
        response.setContentType("application/json");
        new ObjectMapper().writeValue(response.getOutputStream(),idToken);
        //response.setHeader("Authorization",jwtAccessToken);
    }
}

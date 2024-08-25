package com.ecaj.secservice.security.filters;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.ecaj.secservice.security.JWTUtils;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;

public class JwtAuthorizationFilter extends OncePerRequestFilter {
    /**
     * Envoi d'une demande d'une ressource qui nécessite une authentification dans la méthode doFilterInternal
     * Récupération du JWT avec l'objet request
     * Appel de la librairie JWT pour vérifier la signature
     * Récupération de username et les roles en précisant que c'est un tableau de String
     * Authentification de l'utilisateur un objet authenticationToken
     * Conversion des roles String en GrantedAuthority
     * Retour à Spring de l'utilisateur authentifié
     * Spring met en place son contexte de sécurité
     * Laissé passer de la requete grace à l'objet filterChain
     * @param request
     * @param response
     * @param filterChain
     * @throws ServletException
     * @throws IOException
     */
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        if (request.getServletPath().equals("/refreshToken")){
            filterChain.doFilter(request, response);
        }
        else {
            String authorizationToken = request.getHeader(JWTUtils.AUTH_HEADER);
            if (authorizationToken != null && authorizationToken.startsWith(JWTUtils.PREFIX)) {
                try{
                    String jwt = authorizationToken.substring(JWTUtils.PREFIX.length());
                    Algorithm algorithm = Algorithm.HMAC256(JWTUtils.SECRET);
                    JWTVerifier jwtVerifier = JWT.require(algorithm).build();
                    DecodedJWT decodedJWT = jwtVerifier.verify(jwt);
                    String username = decodedJWT.getSubject();
                    String[] roles = decodedJWT.getClaim("roles").asArray(String.class);
                    Collection<GrantedAuthority> authorities = new ArrayList<>();
                    for (String role: roles) {
                        authorities.add(new SimpleGrantedAuthority(role));
                    }
                    UsernamePasswordAuthenticationToken authenticationToken =
                            new UsernamePasswordAuthenticationToken(username, null, authorities);
                    SecurityContextHolder.getContext().setAuthentication(authenticationToken);
                    filterChain.doFilter(request, response);
                }
                catch (Exception e){
                    response.setHeader("error-message",e.getMessage());
                    response.sendError(HttpServletResponse.SC_FORBIDDEN);
                }
            }
            else {
                filterChain.doFilter(request, response);
            }
        }

    }
}

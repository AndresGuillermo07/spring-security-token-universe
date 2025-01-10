package com.app.SpringSecurityApp.config.filter;

import com.app.SpringSecurityApp.util.JwtUtils;
import com.auth0.jwt.interfaces.DecodedJWT;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpHeaders;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Collection;

public class JwtTokenValidator extends OncePerRequestFilter {

    private JwtUtils jwtUtils;

    public JwtTokenValidator(JwtUtils jwtUtils) {
        this.jwtUtils = jwtUtils;
    }

    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request,
                                    @NonNull HttpServletResponse response,
                                    @NonNull FilterChain filterChain) throws ServletException, IOException {

        String jwtToken = request.getHeader(HttpHeaders.AUTHORIZATION);

        if (jwtToken != null && jwtToken.startsWith("Bearer ")) { // Verify that the token is not null and that it starts with the prefix "Bearer ".
            jwtToken = jwtToken.substring(7); // Remove the "Bearer" prefix from the token to get the clean token.

            DecodedJWT decodedJWT = jwtUtils.verifyToken(jwtToken); // first, validate token

            String username = jwtUtils.extractUsername(decodedJWT); // Extracts the username from the decoded JWT token.
            String stringAuthorities = jwtUtils.getSpecificClaim(decodedJWT,"authorities").asString(); // Gets the value of the specific claim "authorities" of the JWT token as a string.

            Collection<? extends GrantedAuthority> authorities = AuthorityUtils.commaSeparatedStringToAuthorityList(stringAuthorities); // Converts the comma-separated string of authorities to a collection of GrantedAuthority objects.

            SecurityContext securityContext = SecurityContextHolder.getContext(); // Gets the current security context, which stores the user's authentication.
            Authentication authentication = new UsernamePasswordAuthenticationToken(username,null,authorities); // Creates an authentication object with the username, null credentials, and authorities.

            securityContext.setAuthentication(authentication); // Sets the authentication object to the security context.
            SecurityContextHolder.setContext(securityContext); // Updates the security context with the new authenticated context.
        }
        filterChain.doFilter(request, response);



    }
}

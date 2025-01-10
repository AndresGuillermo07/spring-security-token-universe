package com.app.SpringSecurityApp.service;

import com.app.SpringSecurityApp.controller.dto.AuthCreateUserRequest;
import com.app.SpringSecurityApp.controller.dto.AuthLoginRequest;
import com.app.SpringSecurityApp.controller.dto.AuthResponse;
import com.app.SpringSecurityApp.persistence.entity.RoleEntity;
import com.app.SpringSecurityApp.persistence.entity.UserEntity;
import com.app.SpringSecurityApp.persistence.repository.IRoleRepository;
import com.app.SpringSecurityApp.persistence.repository.IUserRepository;
import com.app.SpringSecurityApp.util.JwtUtils;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;


@Service
public class UserDetailServiceImpl implements UserDetailsService {

    private PasswordEncoder passwordEncoder;

    private JwtUtils jwtUtils;

    private final IUserRepository userRepository;

    private final IRoleRepository roleRepository;

    public UserDetailServiceImpl(PasswordEncoder passwordEncoder, JwtUtils jwtUtils, IUserRepository userRepository, IRoleRepository roleRepository) {
        this.passwordEncoder = passwordEncoder;
        this.jwtUtils = jwtUtils;
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        UserEntity userEntity = userRepository.findUserEntityByUsername(username).orElseThrow(
                () -> new UsernameNotFoundException("The user: " + username + " was not found")
        );

        List<SimpleGrantedAuthority> authorities = new ArrayList<>();

        userEntity.getRoles().forEach(role -> authorities.add(
                new SimpleGrantedAuthority("ROLE_".concat(
                        role.getRoleEnum().name()
                )
                )));

        userEntity.getRoles().stream()
                .flatMap(role -> role.getPermissionList().stream())
                .forEach(permission -> authorities.add(new SimpleGrantedAuthority(permission.getName())));

        return new User(userEntity.getUsername(),
                userEntity.getPassword(),
                userEntity.getIsEnable(),
                userEntity.getAccountNonExpired(),
                userEntity.getCredentialsNonExpired(),
                userEntity.getAccountNonLocked(),
                authorities
        );
    }

    public AuthResponse loginUser(AuthLoginRequest authLoginRequest) {
        String username = authLoginRequest.username();
        String password = authLoginRequest.password();

        Authentication authentication = this.authenticate(username,password);
        SecurityContextHolder.getContext().setAuthentication(authentication);

        String accessToken = jwtUtils.createToken(authentication);

        return new AuthResponse(username,"User logged successfully",accessToken,true);
    }

    private Authentication authenticate(String username, String password) {
        UserDetails userDetails = loadUserByUsername(username);

        if(userDetails == null) {
            throw new BadCredentialsException("Invalid username or password");
        }

        if(!passwordEncoder.matches(password, userDetails.getPassword())) {
            throw new BadCredentialsException("Invalid password");
        }

        return new UsernamePasswordAuthenticationToken(userDetails, userDetails.getPassword(), userDetails.getAuthorities());
    }

    public AuthResponse createUser(AuthCreateUserRequest authCreateUserRequest) {

        String username = authCreateUserRequest.username();
        String password = authCreateUserRequest.password();
        List<String> roleRequest = authCreateUserRequest.roleRequest().roleListName();

        Set<RoleEntity> roleEntitySet = roleRepository.findRoleEntitiesByRoleEnumIn(roleRequest).stream().collect(Collectors.toSet());

        if (roleEntitySet.isEmpty()) {
            throw new IllegalArgumentException("None of the specified roles exist: " + roleRequest);
        }

        if (username == null || username.isBlank() || password == null || password.isBlank()) {
            throw new IllegalArgumentException("Username or password cannot be empty.");
        }
        if (roleRequest == null || roleRequest.isEmpty()) {
            throw new IllegalArgumentException("Role list cannot be empty.");
        }



        UserEntity newUser = UserEntity.builder()
                .username(username)
                .password(passwordEncoder.encode(password))
                .roles(roleEntitySet)
                .isEnable(true)
                .accountNonLocked(true)
                .accountNonExpired(true)
                .credentialsNonExpired(true)
                .build();

        UserEntity userCreated = userRepository.save(newUser);

        List<SimpleGrantedAuthority> authorityList = userCreated.getRoles().stream()
                .flatMap(role -> Stream.concat(
                        Stream.of(new SimpleGrantedAuthority("ROLE_" + role.getRoleEnum().name())),
                        role.getPermissionList().stream().map(permission -> new SimpleGrantedAuthority(permission.getName()))
                ))
                .collect(Collectors.toList());

        UserDetails userDetails = new User(username,
                passwordEncoder.encode(password),
                authorityList
        );

        Authentication authentication = new UsernamePasswordAuthenticationToken(userDetails,
                null,
                authorityList
        );

        String accessToken = jwtUtils.createToken(authentication);
        System.out.println("Generated Token: " + accessToken);

        AuthResponse authResponse = new AuthResponse(username,"User logged successfully",accessToken,true);

        return authResponse;
    }
}

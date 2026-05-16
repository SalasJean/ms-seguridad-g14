package com.codigo.ms_seguridad.service.impl;

import com.codigo.ms_seguridad.aggregates.constants.Constants;
import com.codigo.ms_seguridad.aggregates.request.SignInRequest;
import com.codigo.ms_seguridad.aggregates.request.SignUpRequest;
import com.codigo.ms_seguridad.aggregates.response.SignInResponse;
import com.codigo.ms_seguridad.entity.Rol;
import com.codigo.ms_seguridad.entity.Role;
import com.codigo.ms_seguridad.entity.Usuario;
import com.codigo.ms_seguridad.repository.RolRepository;
import com.codigo.ms_seguridad.repository.UsuarioRepository;
import com.codigo.ms_seguridad.service.AuthenticationService;
import com.codigo.ms_seguridad.service.JwtService;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.*;

@Service
@RequiredArgsConstructor
@Log4j2
public class AuthenticationServiceImpl implements AuthenticationService {

    private final UsuarioRepository usuarioRepository;
    private final RolRepository rolRepository;
    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;


    @Override
    public Usuario signUpUser(SignUpRequest signUpRequest) {
        Usuario usuario = getUsuarioEntity(signUpRequest);
        usuario.setRoles(Collections.singleton(getRoles(Role.USER)));
        return usuarioRepository.save(usuario);
    }

    @Override
    public Usuario signUpAdmin(SignUpRequest signUpRequest) {
        Usuario userAdmin = getUsuarioEntity(signUpRequest);
        Set<Rol> roles = new HashSet<>();
        //roles.add(getRoles(Role.USER));
        roles.add(getRoles(Role.ADMIN));
        userAdmin.setRoles(roles);
        return usuarioRepository.save(userAdmin);
    }

    @Override
    public List<Usuario> todos() {
        return usuarioRepository.findAll();
    }

    @Override
    public SignInResponse signIn(SignInRequest signInRequest) {
        //Autenticacion con las credenciales (email y password)
        authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(
                signInRequest.getEmail(),signInRequest.getPassword()));
        //Buscar al usuario en BD
        Usuario usuario = usuarioRepository.findByEmail(signInRequest.getEmail())
                .orElseThrow(() -> new UsernameNotFoundException("Usuario no encontrado en la BD"));

        //Generar el token
        String accessToken = jwtService.generateToken(usuario);
        String refreshToken = jwtService.generateRefreshToken(new HashMap<>(), usuario);

        //Devuelvo la respuesta
        return SignInResponse.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .build();
    }

    @Override
    public SignInResponse getRokenByRefreshToken(String refreshToken) {
        //Validar que sea un REFRESH TOKEN
        if(!jwtService.validateIsRefreshToken(refreshToken)){
            throw new RuntimeException("ERROR: Token ingresado no es de tipo REFRESH");
        }
        //Extraer el username del token
        String userEmail = jwtService.extractUserName(refreshToken);

        //Cargar al usuario de BD
        Usuario usuario = usuarioRepository.findByEmail(userEmail)
                .orElseThrow(()-> new UsernameNotFoundException("ERROR: Usuario no encontrado en BD"));

        if(!jwtService.validateToken(refreshToken,usuario)){
            throw new IllegalStateException("ERROR: Token ingresado no es Valido o esta VENCIDO");
        }

        //Generar el nuevo access
        String newAccess = jwtService.generateToken(usuario);
        return SignInResponse.builder()
                .accessToken(newAccess)
                .refreshToken(refreshToken).build();
    }

    private Usuario getUsuarioEntity(SignUpRequest signUpRequest){
        return Usuario.builder()
                .nombres(signUpRequest.getNombres())
                .apellidos(signUpRequest.getApellidos())
                .email(signUpRequest.getEmail())
                .password(new BCryptPasswordEncoder().encode(signUpRequest.getPassword()))
                .tipoDoc(signUpRequest.getTipoDoc())
                .numDoc(signUpRequest.getNumDoc())
                .isAccountNonExpired(Constants.STATUS_ACTIVE)
                .isAccountNonLocked(Constants.STATUS_ACTIVE)
                .isCredentialsNonExpired(Constants.STATUS_ACTIVE)
                .isEnabled(Constants.STATUS_ACTIVE)
                .build();
    }

    private Rol getRoles(Role rolBuscado){
        return rolRepository.findByNombreRol(rolBuscado.name())
                .orElseThrow(() -> new RuntimeException("Error el rol no exixte: " + rolBuscado.name()));
    }
}

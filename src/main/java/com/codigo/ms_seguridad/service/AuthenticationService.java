package com.codigo.ms_seguridad.service;

import com.codigo.ms_seguridad.aggregates.request.SignInRequest;
import com.codigo.ms_seguridad.aggregates.request.SignUpRequest;
import com.codigo.ms_seguridad.aggregates.response.SignInResponse;
import com.codigo.ms_seguridad.entity.Usuario;

import java.util.List;

public interface AuthenticationService {
    //Registrar Usuario
    Usuario signUpUser(SignUpRequest signUpRequest);
    //Registrar Admin
    Usuario signUpAdmin(SignUpRequest signUpRequest);
    List<Usuario> todos();
    SignInResponse signIn(SignInRequest signInRequest);
    SignInResponse getRokenByRefreshToken(String refreshToken);


}

package com.codigo.ms_seguridad.service;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;

public interface UsuarioService {
    UserDetailsService userDetailsService();
}

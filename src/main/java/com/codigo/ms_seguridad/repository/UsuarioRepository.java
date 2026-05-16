package com.codigo.ms_seguridad.repository;

import com.codigo.ms_seguridad.entity.Usuario;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.Optional;

public interface UsuarioRepository
        extends JpaRepository<Usuario,Long> {
    Optional<Usuario> findByEmail(String email);
    @Query("")
    Optional<Usuario> findByApellidos(String apellidos);
}

package com.codigo.ms_seguridad.config;

import com.codigo.ms_seguridad.service.JwtService;
import com.codigo.ms_seguridad.service.UsuarioService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final UsuarioService usuarioService;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        final String tokenExtraidoHeader = request.getHeader("Authorization");

        if (!StringUtils.hasText(tokenExtraidoHeader) || !tokenExtraidoHeader.startsWith("Bearer ")){
                filterChain.doFilter(request, response);
                return;

                //null
            //""
            //" "

            //Basic abc123
        }

        //Bearer xjhsbjuxcaksl
        //xjhsbjuxcaksl
        String token = tokenExtraidoHeader.substring(7);
        String username = jwtService.extractUserName(token);

        if(username != null && SecurityContextHolder.getContext().getAuthentication() == null){
            UserDetails userDetails =
                    usuarioService.userDetailsService().loadUserByUsername(username);
            if(jwtService.validateToken(token, userDetails) &&
                    !jwtService.validateIsRefreshToken(token)){
                UsernamePasswordAuthenticationToken authentication =
                        new UsernamePasswordAuthenticationToken(userDetails,
                                null, userDetails.getAuthorities());

                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                SecurityContext context = SecurityContextHolder.createEmptyContext();
                context.setAuthentication(authentication);

                SecurityContextHolder.setContext(context);

            }

        }
        filterChain.doFilter(request,response);
    }
}

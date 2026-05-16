package com.codigo.ms_seguridad.service.impl;

import com.codigo.ms_seguridad.aggregates.constants.Constants;
import com.codigo.ms_seguridad.entity.Usuario;
import com.codigo.ms_seguridad.service.JwtService;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

@Component
public class JwtServiceImpl implements JwtService {

    @Value("${key.signature}")
    private String keySignature;


    @Override
    public String extractUserName(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    @Override
    public String generateToken(Usuario usuario) {
        Map<String,Object> claims = addClaims(usuario);
        claims.put("type", Constants.ACCESS);
        claims.put("id",usuario.getId());
        claims.put("nombres", usuario.getNombres());
        claims.put("apellidos", usuario.getApellidos());
        claims.put("dni", usuario.getNumDoc());

        Date now = new Date();
        Date expiration  = new Date(now.getTime() + 60000);
        return Jwts.builder()
                .setHeaderParam("typ","JWT")
                .setClaims(claims)
                .setSubject(usuario.getUsername())
                .setIssuedAt(now)
                .setExpiration(expiration)
                .claim("datoExtra",123456)
                .signWith(getSignKey(), SignatureAlgorithm.HS512)
                .compact();
    }

    private Map<String, Object> addClaims(Usuario usuario) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("accountNonExpired",usuario.isAccountNonExpired());
        claims.put("accountNonLocked",usuario.isAccountNonLocked());
        claims.put("credentialsNonExpired",usuario.isCredentialsNonExpired());
        claims.put("enabled",usuario.isEnabled());
        claims.put("roles", usuario.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toList()));
        return claims;
    }

    @Override
    public boolean validateToken(String token, UserDetails userDetails) {
        final String username = extractUserName(token);
        return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
    }

    @Override
    public String generateRefreshToken(Map<String, Object> extraClaims, UserDetails userDetails) {
        return Jwts.builder()
                .setClaims(extraClaims != null? extraClaims:new HashMap<>())
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + 600000))
                .claim("type",Constants.REFRESH)
                .signWith(getSignKey(), SignatureAlgorithm.HS512)
                .compact();
    }

    @Override
    public boolean validateIsRefreshToken(String token) {
        Claims claims = extractAllClaims(token);
        String typeToken = claims.get("type",String.class);
        return Constants.REFRESH.equalsIgnoreCase(typeToken);
    }

    private Key getSignKey(){
        byte[] key = Decoders.BASE64.decode(keySignature);
        return Keys.hmacShaKeyFor(key);
    }

    private Claims extractAllClaims(String token){
        return Jwts.parserBuilder()
                .setSigningKey(getSignKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    private <T> T extractClaim(String token,
                               Function<Claims, T> claimsTFunction){
        return claimsTFunction.apply(extractAllClaims(token));
    }

    private boolean isTokenExpired(String token){
        return extractClaim(token, Claims::getExpiration).before(new Date());
    }

}

package br.com.rodolfo.pontointeligente.api.security;

import java.util.ArrayList;
import java.util.List;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import br.com.rodolfo.pontointeligente.api.entities.Funcionario;
import br.com.rodolfo.pontointeligente.api.enums.PerfilEnum;

/**
 * Converter o Usuário (funcionário) para o JWT User do Spring Security
 */
public class JwtUserFactory {

    private JwtUserFactory() {}

    /**
     * Converte e gera um JwtUser com base nos dados de um funcioário.
     * 
     * @param usuario
     * @return JwtUser
     */
    public static JwtUser create(Funcionario usuario) {
        
        return new JwtUser(usuario.getId(), 
                           usuario.getEmail(), 
                           usuario.getSenha(), 
                           mapToGrantedAuthorities(usuario.getPerfil()));
    }

    /**
     * Converte o perfil do usuário para o formato utilizado pelo Spring Security
     * 
     * @param perfilEnum
     * @return List<GrantedAuthority>
     */
    private static List<GrantedAuthority> mapToGrantedAuthorities(PerfilEnum perfilEnum) {
        
        List<GrantedAuthority> authorities = new ArrayList<GrantedAuthority>();
        authorities.add(new SimpleGrantedAuthority(perfilEnum.toString()));

        return authorities;
    }
    
}
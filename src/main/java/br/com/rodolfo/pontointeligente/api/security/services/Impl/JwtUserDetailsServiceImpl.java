package br.com.rodolfo.pontointeligente.api.security.services.Impl;

import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import br.com.rodolfo.pontointeligente.api.entities.Funcionario;
import br.com.rodolfo.pontointeligente.api.security.JwtUserFactory;
import br.com.rodolfo.pontointeligente.api.services.FuncionarioService;

/**
 * Essa classe deve ser implementada para obter as informações do usuário
 */
@Service
public class JwtUserDetailsServiceImpl implements UserDetailsService {

    @Autowired
    FuncionarioService funcionarioService;

	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        
        Optional<Funcionario> funcionario = funcionarioService.buscarPorEmail(username);
        
        if(funcionario.isPresent()) {

            return JwtUserFactory.create(funcionario.get());
        }


        throw new UsernameNotFoundException("Email não encontrado.");
	}

    
}
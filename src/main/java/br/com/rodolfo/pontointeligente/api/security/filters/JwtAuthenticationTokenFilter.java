package br.com.rodolfo.pontointeligente.api.security.filters;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;

import br.com.rodolfo.pontointeligente.api.security.utils.JwtTokenUtil;

/**
 * Filtro (interceptor) para validar as requisições
 */
public class JwtAuthenticationTokenFilter extends OncePerRequestFilter{

    private static final String AUTH_HEADER = "Authorization";
    private static final String BEARER_PREFIX = "Bearer ";

    @Autowired
    private UserDetailsService userDetailsService;

    @Autowired
    private JwtTokenUtil jwtTokenUtil;
    
    //Esse método será invocado em todas as requisições ao servidor para realização da validação
    @Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
        
        //Obter o token do header
        String token = request.getHeader(AUTH_HEADER);

        //Extrair o prefixo Bearer
        if(token != null && token.startsWith(BEARER_PREFIX)) {

            token = token.substring(7);
        }

        //Pegar o nome do usuário no token
        String username = jwtTokenUtil.getUserNameFromToken(token);

        if(username != null && SecurityContextHolder.getContext().getAuthentication() == null) {

            UserDetails userDetails = this.userDetailsService.loadUserByUsername(username);

            if(jwtTokenUtil.tokenValido(token)) {

                UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                                                                            userDetails, 
                                                                            null, 
                                                                            userDetails.getAuthorities()
                                                                        );
                                                        
                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authentication);
            }
        }

        filterChain.doFilter(request, response);
	}

}
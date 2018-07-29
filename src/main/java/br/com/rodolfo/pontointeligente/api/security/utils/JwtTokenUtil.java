package br.com.rodolfo.pontointeligente.api.security.utils;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import br.com.rodolfo.pontointeligente.api.entities.Funcionario;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

/**
 * Responsável por realizar todo o controle do TOKEN JWT
 */
@Component
public class JwtTokenUtil {

    static final String CLAIM_KEY_USERNAME = "sub";
    static final String CLAIM_KEY_ROLE = "role";
    static final String CLAIM_KEY_CREATED = "created";
    
    @Value("${jwt.secret}")
    private String secret;

    @Value("${jwt.expiration}")
    private Long expiration;


    /**
     * Obtém o username (email) contido no TOKEN JWT
     * 
     * @param token
     * @return String
     */
    public String getUserNameFromToken(String token) {

        String username;

        try {
            
            //Claims é o nome dado aos atributos dentro do token
            Claims claims = getClaimsFromToken(token);
            username = claims.getSubject();

        } catch (Exception e) {
            
            username = null;
        }
        
        return username;
    }

    /**
     * Retorna a data de expiração de um TOKEN JWT
     * Verificar se um TOKEN está expirado ou não
     * 
     * @param token
     * @return Date
     */
    public Date getExpirationDateFromToken(String token) {

        Date expiration;

        try {
            
            Claims claims = getClaimsFromToken(token);
            expiration = claims.getExpiration();

        } catch (Exception e) {
            
            expiration = null;
        }

        return expiration;
    }

    /**
     * Criar um novo TOKEN JWT
     * 
     * @param token
     * @return String
     */
    public String refreshToken(String token) {
        
        String refreshToken;

        try {
            
            Claims claims = getClaimsFromToken(token);
            claims.put(CLAIM_KEY_CREATED, new Date());
            refreshToken = gerarToken(claims);

        } catch (Exception e) {
            
            refreshToken = null;
        }

        return refreshToken;
    }

    /**
     * Verifica e retorna se um TOKEN JWT é válido
     * 
     * @param token
     * @return boolean
     */
    public boolean tokenValido(String token) {
        
        return !tokenExpirado(token);
    }


    /**
     * Retorna um novo TOKEN JWT com base nos dados do usuário
     * 
     * @param funcionario
     * @return String
     */
    public String obterToken(UserDetails userDetails) {
        
        //UserDetail é uma classe do Security

        Map<String,Object> claims = new HashMap<>();
        claims.put(CLAIM_KEY_USERNAME, userDetails.getUsername());
        userDetails.getAuthorities().forEach(authorite -> claims.put(CLAIM_KEY_ROLE, authorite.getAuthority()));
        claims.put(CLAIM_KEY_CREATED, new Date());

        return this.gerarToken(claims);
    }

    /**
     * Retorna a data de expiracao com base na data atual
     * 
     * @return Date
     */
    public Date gerarDataExpiracao() {
        
        return new Date(System.currentTimeMillis() + this.expiration * 1000);
    }


    /**
     * Verifica se um TOKEN JWT está expirado 
     * 
     * @param token
     * @return boolean
     */
    private boolean tokenExpirado(String token) {
        
        Date dataExpiracao = this.getExpirationDateFromToken(token);
        
        if(dataExpiracao == null) {

            return false;
        }
        
        //Token é expirado se a data dele for anterior a data atual
        return dataExpiracao.before(new Date());
	}

	/**
     * Realiza o parse do token para extrair as informações
     * 
     * @param token
     * @return Claims
     */
	private Claims getClaimsFromToken(String token) {
        
        Claims claims;

        try {
            
            claims = Jwts.parser().setSigningKey(this.secret).parseClaimsJws(token).getBody();

        } catch (Exception e) {
            
            claims = null;
        }
        
        return claims;
    }
    
    /**
     * Gerar um novo TOKEN JWT com os dados (claims) fornecidos 
     * 
     * @param claims
     * @return String
     */
    private String gerarToken(Map<String, Object> claims) {
        
        return Jwts.builder().setClaims(claims).setExpiration(this.gerarDataExpiracao())
                .signWith(SignatureAlgorithm.HS512, this.secret).compact();
    }

}
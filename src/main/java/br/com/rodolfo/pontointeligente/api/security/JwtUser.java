package br.com.rodolfo.pontointeligente.api.security;

import java.util.Collection;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

/**
 * Representação do objeto Funcionario no padrão do Spring Security
 */
public class JwtUser implements UserDetails {

    private static final long serialVersionUID = 1L;
    
    private Long id;
    private String userName;
    private String password;
    private Collection<? extends GrantedAuthority> authorities;

    public JwtUser(Long id, String userName, 
                   String password, Collection<? extends GrantedAuthority> authorities) {

        this.id = id;
        this.userName = userName;
        this.password = password;
        this.authorities = authorities;
    }

	@Override
	public Collection<? extends GrantedAuthority> getAuthorities() {
		return authorities;
	}

	@Override
	public String getPassword() {
		return password;
	}

	@Override
	public String getUsername() {
		return userName;
	}

	@Override
	public boolean isAccountNonExpired() {
		return true;
	}

	@Override
	public boolean isAccountNonLocked() {
		return true;
	}

	@Override
	public boolean isCredentialsNonExpired() {
		return true;
	}

	@Override
	public boolean isEnabled() {
		return true;
	}

    
}
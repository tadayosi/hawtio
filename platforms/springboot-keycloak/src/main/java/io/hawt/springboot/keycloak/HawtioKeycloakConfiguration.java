package io.hawt.springboot.keycloak;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import org.keycloak.OAuth2Constants;
import org.keycloak.adapters.OAuthRequestAuthenticator;
import org.keycloak.adapters.springsecurity.KeycloakConfiguration;
import org.keycloak.adapters.springsecurity.authentication.SpringSecurityRequestAuthenticator;
import org.keycloak.adapters.springsecurity.config.KeycloakWebSecurityConfigurerAdapter;
import org.keycloak.adapters.springsecurity.filter.KeycloakAuthenticationProcessingFilter;
import org.keycloak.common.util.Base64Url;
import org.keycloak.common.util.KeycloakUriBuilder;
import org.keycloak.common.util.SecretGenerator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.web.servlet.ServletListenerRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.PropertySource;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.core.session.SessionRegistryImpl;
import org.springframework.security.web.authentication.session.RegisterSessionAuthenticationStrategy;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.session.HttpSessionEventPublisher;

@KeycloakConfiguration
@EnableWebSecurity
@PropertySource("classpath:/io/hawt/springboot/keycloak/application.properties")
public class HawtioKeycloakConfiguration extends KeycloakWebSecurityConfigurerAdapter {

    /**
     * Registers the KeycloakAuthenticationProvider with the authentication manager.
     */
    @Autowired
    public void configureGlobal(AuthenticationManagerBuilder auth) {
        auth.authenticationProvider(keycloakAuthenticationProvider());
    }

    /**
     * Defines the session authentication strategy.
     */
    @Bean
    @Override
    protected SessionAuthenticationStrategy sessionAuthenticationStrategy() {
        return new RegisterSessionAuthenticationStrategy(new SessionRegistryImpl());
    }

    @Bean
    protected SessionRegistry buildSessionRegistry() {
        return new SessionRegistryImpl();
    }

    /**
     * Defines Spring Security session listener.
     */
    @Bean
    public ServletListenerRegistrationBean<HttpSessionEventPublisher> httpSessionEventPublisher() {
        return new ServletListenerRegistrationBean<>(new HttpSessionEventPublisher());
    }

    /**
     * Workaround: TODO JIRA
     */
    @Override
    protected KeycloakAuthenticationProcessingFilter keycloakAuthenticationProcessingFilter() throws Exception {
        KeycloakAuthenticationProcessingFilter filter = super.keycloakAuthenticationProcessingFilter();
        filter.setRequestAuthenticatorFactory((facade, request, deployment, tokenStore, sslRedirectPort) ->
            new SpringSecurityRequestAuthenticator(facade, request, deployment, tokenStore, sslRedirectPort) {
                @Override
                protected OAuthRequestAuthenticator createOAuthAuthenticator() {
                    return new OAuthRequestAuthenticator(this, facade, deployment, sslRedirectPort, tokenStore) {
                        @Override
                        protected String getRedirectUri(String state) {
                            String uri = super.getRedirectUri(state);
                            if (!deployment.isPkce()) {
                                return uri;
                            }

                            // PKCE support
                            try {
                                String codeVerifier = SecretGenerator.getInstance().randomString(128);
                                MessageDigest md = MessageDigest.getInstance("SHA-256");
                                md.update(codeVerifier.getBytes(StandardCharsets.ISO_8859_1));
                                String codeChallenge = Base64Url.encode(md.digest());
                                KeycloakUriBuilder uriBuilder = KeycloakUriBuilder.fromUri(uri);
                                uriBuilder.queryParam(OAuth2Constants.CODE_CHALLENGE, codeChallenge);
                                uriBuilder.queryParam(OAuth2Constants.CODE_CHALLENGE_METHOD, "S256");
                                return uriBuilder.buildAsString();
                            } catch (NoSuchAlgorithmException e) {
                                throw new RuntimeException(e);
                            }
                        }
                    };
                }
            });
        return filter;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        super.configure(http);
        http.authorizeRequests().anyRequest().authenticated()
            .and()
            .formLogin()
            .and()
            .httpBasic()
            .and()
            .csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse());
    }

}

package io.hawt.springboot;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import javax.servlet.http.HttpServletRequest;

import io.hawt.system.ConfigManager;
import io.hawt.util.Strings;
import io.hawt.web.auth.AuthenticationFilter;
import io.hawt.web.auth.LoginServlet;
import io.hawt.web.auth.LogoutServlet;
import io.hawt.web.auth.SessionExpiryFilter;
import io.hawt.web.auth.keycloak.KeycloakServlet;
import io.hawt.web.auth.keycloak.KeycloakUserServlet;
import io.hawt.web.filters.CORSFilter;
import io.hawt.web.filters.CacheHeadersFilter;
import io.hawt.web.filters.XFrameOptionsFilter;
import io.hawt.web.filters.XXSSProtectionFilter;
import io.hawt.web.proxy.ProxyServlet;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.actuate.autoconfigure.ManagementContextConfiguration;
import org.springframework.boot.actuate.autoconfigure.ManagementServerProperties;
import org.springframework.boot.actuate.endpoint.mvc.JolokiaMvcEndpoint;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.web.ServerProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.boot.web.servlet.ServletListenerRegistrationBean;
import org.springframework.boot.web.servlet.ServletRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.PropertySource;
import org.springframework.core.Ordered;
import org.springframework.web.servlet.handler.SimpleUrlHandlerMapping;
import org.springframework.web.servlet.mvc.AbstractUrlViewController;

/**
 * Management context configuration for hawtio on Spring Boot.
 */
@ManagementContextConfiguration
@ConditionalOnBean(HawtioEndpoint.class)
@PropertySource("classpath:/io/hawt/springboot/application.properties")
public class HawtioConfiguration {

    private final String managementContextPath;
    private final String hawtioPath;

    @Autowired
    public HawtioConfiguration(
        final ServerProperties serverProperties,
        final ManagementServerProperties managementServerProperties,
        final HawtioEndpoint hawtioEndpoint) {
        final int serverPort = getOrDefault(serverProperties.getPort(), 8080);
        final int managementPort = getOrDefault(managementServerProperties.getPort(),
                                                serverPort);

        final String prefix;
        if (serverPort == managementPort) {
            prefix = Strings.webContextPath(serverProperties.getServletPrefix());
        } else {
            prefix = "";
        }

        this.managementContextPath = Strings.webContextPath(prefix,
                                                            managementServerProperties.getContextPath());
        this.hawtioPath = Strings.webContextPath(managementContextPath,
                                                 hawtioEndpoint.getPath());
    }

    @Autowired
    public void initializeHawtioPlugins(final HawtioEndpoint hawtioEndpoint,
                                        final Optional<List<HawtPlugin>> plugins) {
        hawtioEndpoint.setPlugins(plugins.orElse(Collections.emptyList()));
    }

    @Bean
    @ConditionalOnBean(JolokiaMvcEndpoint.class)
    public SimpleUrlHandlerMapping hawtioUrlMapping(
        final ManagementServerProperties managementServerProperties,
        final HawtioEndpoint hawtioEndpoint,
        final JolokiaMvcEndpoint jolokiaEndpoint) {
        final String hawtioPath = Strings.webContextPath(hawtioEndpoint.getPath());
        final String jolokiaPath = Strings.webContextPath(jolokiaEndpoint.getPath());

        final SilentSimpleUrlHandlerMapping mapping = new SilentSimpleUrlHandlerMapping();
        final Map<String, Object> urlMap = new HashMap<>();

        if (!hawtioPath.isEmpty() || !"/jolokia".equals(jolokiaPath)) {
            final String hawtioJolokiaPath = Strings.webContextPath(
                managementServerProperties.getContextPath(), hawtioPath,
                "jolokia", "**");
            urlMap.put(hawtioJolokiaPath,
                       new JolokiaForwardingController(jolokiaEndpoint.getPath()));
            mapping.setOrder(Ordered.HIGHEST_PRECEDENCE);
        } else {
            urlMap.put(SilentSimpleUrlHandlerMapping.DUMMY, null);
        }

        mapping.setUrlMap(urlMap);
        return mapping;
    }

    // -------------------------------------------------------------------------
    // Filters
    // -------------------------------------------------------------------------


    @Bean
    public FilterRegistrationBean sessionExpiryFilter() {
        final FilterRegistrationBean filter = new FilterRegistrationBean();
        filter.setFilter(new SessionExpiryFilter());
        filter.addUrlPatterns(hawtioPath + "/*");
        return filter;
    }

    @Bean
    public FilterRegistrationBean cacheFilter() {
        final FilterRegistrationBean filter = new FilterRegistrationBean();
        filter.setFilter(new CacheHeadersFilter());
        filter.addUrlPatterns(hawtioPath + "/*");
        return filter;
    }

    @Bean
    public FilterRegistrationBean hawtioCorsFilter() {
        final FilterRegistrationBean filter = new FilterRegistrationBean();
        filter.setFilter(new CORSFilter());
        filter.addUrlPatterns(hawtioPath + "/*");
        return filter;
    }

    @Bean
    public FilterRegistrationBean xframeOptionsFilter() {
        final FilterRegistrationBean filter = new FilterRegistrationBean();
        filter.setFilter(new XFrameOptionsFilter());
        filter.addUrlPatterns(hawtioPath + "/*");
        return filter;
    }

    @Bean
    public FilterRegistrationBean xxssProtectionFilter() {
        final FilterRegistrationBean filter = new FilterRegistrationBean();
        filter.setFilter(new XXSSProtectionFilter());
        filter.addUrlPatterns(hawtioPath + "/*");
        return filter;
    }

    @Bean
    public FilterRegistrationBean authenticationFilter(final Optional<JolokiaMvcEndpoint> jolokiaEndpoint) {
        final FilterRegistrationBean filter = new FilterRegistrationBean();
        filter.setFilter(new AuthenticationFilter());
        filter.addUrlPatterns(hawtioPath + "/auth/*");
        if (jolokiaEndpoint.isPresent() && !jolokiaEndpoint.get().getPath().isEmpty()) {
            filter.addUrlPatterns(
                Strings.webContextPath(managementContextPath, jolokiaEndpoint.get().getPath(), "*"));
        }
        return filter;
    }

    // -------------------------------------------------------------------------
    // Servlets
    // -------------------------------------------------------------------------

    // Jolokia agent servlet is provided by Spring Boot actuator

    @Bean
    public ServletRegistrationBean jolokiaProxyServlet() {
        return new ServletRegistrationBean(
            new ProxyServlet(),
            hawtioPath + "/proxy/*");
    }

    @Bean
    public ServletRegistrationBean userServlet() {
        return new ServletRegistrationBean(
            new KeycloakUserServlet(),
            managementContextPath + "/user/*",
            hawtioPath + "/user/*");
    }

    @Bean
    public ServletRegistrationBean loginServlet() {
        return new ServletRegistrationBean(
            new LoginServlet(),
            hawtioPath + "/auth/login");
    }

    @Bean
    public ServletRegistrationBean logoutServlet() {
        return new ServletRegistrationBean(
            new LogoutServlet(),
            hawtioPath + "/auth/logout");
    }

    @Bean
    public ServletRegistrationBean keycloakServlet() {
        return new ServletRegistrationBean(
            new KeycloakServlet(),
            hawtioPath + "/keycloak/*");
    }

    // -------------------------------------------------------------------------
    // Listeners
    // -------------------------------------------------------------------------

    @Bean
    public ServletListenerRegistrationBean<?> hawtioContextListener(
        final ConfigManager configManager) {
        return new ServletListenerRegistrationBean<>(
            new SpringHawtioContextListener(configManager, hawtioPath));
    }

    // -------------------------------------------------------------------------
    // Utilities
    // -------------------------------------------------------------------------

    private static int getOrDefault(final Integer number, final int defaultValue) {
        return number == null ? defaultValue : number;
    }

    private class JolokiaForwardingController extends AbstractUrlViewController {

        private final String jolokiaPath;
        private final int jolokiaSubPathStart;

        JolokiaForwardingController(final String jolokiaPath) {
            this.jolokiaPath = jolokiaPath;
            this.jolokiaSubPathStart = Strings.webContextPath(hawtioPath, "jolokia")
                .length();
        }

        @Override
        protected String getViewNameForRequest(final HttpServletRequest request) {
            String uri = Strings.webContextPath(request.getRequestURI());
            final String jolokiaRequest = uri.substring(
                request.getContextPath().length() + jolokiaSubPathStart);

            final StringBuilder b = new StringBuilder();
            b.append("forward:");
            b.append(Strings.webContextPath(managementContextPath, jolokiaPath,
                                            jolokiaRequest));
            if (request.getQueryString() != null) {
                b.append('?').append(request.getQueryString());
            }

            return b.toString();
        }

    }

    // Does not warn when no mappings are present
    private static class SilentSimpleUrlHandlerMapping
        extends SimpleUrlHandlerMapping {
        private static final String DUMMY = "/<DUMMY>";

        @Override
        protected void registerHandler(final String urlPath, final Object handler) {
            if (!DUMMY.equals(urlPath)) {
                super.registerHandler(urlPath, handler);
            }
        }
    }

}

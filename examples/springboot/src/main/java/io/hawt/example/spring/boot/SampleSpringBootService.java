package io.hawt.example.spring.boot;

import io.hawt.config.ConfigFacade;
import io.hawt.springboot.HawtPlugin;
import io.hawt.web.auth.AuthenticationConfiguration;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

@SpringBootApplication
public class SampleSpringBootService {

    public static void main(String[] args) {
        SpringApplication.run(SampleSpringBootService.class, args);
    }

    /**
     * Loading an example plugin.
     */
    @Bean
    public HawtPlugin samplePlugin() {
        return new HawtPlugin("sample-plugin",
            "plugins",
            "",
            new String[] { "sample-plugin/js/sample-plugin.js" });
    }

    /**
     * Set things up to be in offline mode.
     */
    @Bean
    public ConfigFacade configFacade() {
        return ConfigFacade.getSingleton();
    }
}

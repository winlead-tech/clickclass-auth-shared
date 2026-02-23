package com.clickclass.auth.shared.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;

import java.io.InputStream;

public class SecurityPropertiesLoader {

    private static final String DEFAULT_YAML = "/security.yml";

    /**
     * Carrega o security.yml do classpath e retorna o objeto SecurityProperties
     */
    public static SecurityProperties load() {
        try (InputStream is = SecurityPropertiesLoader.class.getResourceAsStream(DEFAULT_YAML)) {
            if (is == null) {
                throw new RuntimeException("Não foi possível encontrar o arquivo security.yml no classpath");
            }

            ObjectMapper mapper = new ObjectMapper(new YAMLFactory());
            return mapper.readValue(is, SecurityProperties.class);

        } catch (Exception e) {
            throw new RuntimeException("Erro ao carregar security.yml", e);
        }
    }
}
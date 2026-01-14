/*
 * Copyright 2026 Bundesagentur für Arbeit
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package de.arbeitsagentur.keycloak.wallet.issuance.config;

import org.apache.hc.client5.http.classic.HttpClient;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManager;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManagerBuilder;
import org.apache.hc.client5.http.ssl.SSLConnectionSocketFactory;
import org.apache.hc.client5.http.ssl.SSLConnectionSocketFactoryBuilder;
import org.apache.hc.client5.http.config.RequestConfig;
import org.apache.hc.core5.ssl.SSLContextBuilder;
import org.apache.hc.core5.ssl.SSLContexts;
import org.apache.hc.core5.util.Timeout;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.web.client.RestTemplate;

import javax.net.ssl.SSLContext;
import java.io.InputStream;
import java.nio.file.Files;
import java.security.KeyStore;
import java.time.Duration;

@Configuration
public class RestClientConfig {
    private final WalletProperties properties;

    public RestClientConfig(WalletProperties properties) {
        this.properties = properties;
    }

    @Bean
    RestTemplate restTemplate() {
        Duration timeout = Duration.ofSeconds(5);
        HttpComponentsClientHttpRequestFactory factory = new HttpComponentsClientHttpRequestFactory();
        factory.setConnectionRequestTimeout(timeout);
        factory.setReadTimeout(timeout);
        factory.setHttpClient(buildHttpClient(timeout));
        return new RestTemplate(factory);
    }

    private HttpClient buildHttpClient(Duration timeout) {
        RequestConfig requestConfig = RequestConfig.custom()
                .setConnectTimeout(Timeout.of(timeout))
                .setConnectionRequestTimeout(Timeout.of(timeout))
                .setResponseTimeout(Timeout.of(timeout))
                .build();
        try {
            if (properties.tlsKeyStore() != null && Files.exists(properties.tlsKeyStore())) {
                String type = properties.tlsKeyStoreType() != null ? properties.tlsKeyStoreType() : "PKCS12";
                KeyStore keyStore = KeyStore.getInstance(type);
                char[] password = properties.tlsKeyStorePassword() != null
                        ? properties.tlsKeyStorePassword().toCharArray()
                        : new char[0];
                try (InputStream is = Files.newInputStream(properties.tlsKeyStore())) {
                    keyStore.load(is, password);
                }
                SSLContextBuilder builder = SSLContexts.custom().loadKeyMaterial(keyStore, password);
                SSLContext sslContext = builder.build();
                SSLConnectionSocketFactory socketFactory = SSLConnectionSocketFactoryBuilder.create()
                        .setSslContext(sslContext)
                        .build();
                PoolingHttpClientConnectionManager manager = PoolingHttpClientConnectionManagerBuilder.create()
                        .setSSLSocketFactory(socketFactory)
                        .build();
                return HttpClients.custom()
                        .setDefaultRequestConfig(requestConfig)
                        .setConnectionManager(manager)
                        .build();
            }
        } catch (Exception e) {
            throw new IllegalStateException("Unable to configure TLS client", e);
        }
        return HttpClients.custom()
                .setDefaultRequestConfig(requestConfig)
                .build();
    }
}

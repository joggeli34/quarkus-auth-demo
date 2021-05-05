package com.qumea;

import io.quarkus.oidc.OidcTenantConfig;
import io.quarkus.oidc.common.runtime.OidcCommonConfig;
import io.quarkus.oidc.runtime.OidcConfig;
import io.quarkus.runtime.TlsConfig;
import org.jboss.logging.Logger;
import org.keycloak.adapters.KeycloakDeploymentBuilder;
import org.keycloak.adapters.authentication.ClientCredentialsProviderUtils;
import org.keycloak.authorization.client.AuthzClient;
import org.keycloak.authorization.client.Configuration;
import org.keycloak.representations.adapters.config.AdapterConfig;

import javax.enterprise.context.Dependent;
import javax.enterprise.inject.Produces;
import javax.inject.Singleton;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

@Dependent
public class AuthzClientProducer {
    private static final Logger log = Logger.getLogger(AuthzClientProducer.class);

    /**
     * Almost identical implementation to io.quarkus.keycloak.pep.runtime.KeycloakPolicyEnforcerAuthorizer
     */
    @Produces
    @Singleton
    public AuthzClient createAuthzClient(OidcConfig oidcConfig, TlsConfig tlsConfig) {
        AdapterConfig adapterConfig = new AdapterConfig();
        String authServerUrl = oidcConfig.defaultTenant.getAuthServerUrl().get();
        try {
            adapterConfig.setRealm(authServerUrl.substring(authServerUrl.lastIndexOf('/') + 1));
            adapterConfig.setAuthServerUrl(authServerUrl.substring(0, authServerUrl.lastIndexOf("/realms")));
        } catch (Exception cause) {
            throw new RuntimeException("Failed to parse the realm name.", cause);
        }

        adapterConfig.setResource(oidcConfig.defaultTenant.getClientId().get());
        adapterConfig.setCredentials(getCredentials(oidcConfig.defaultTenant));

        boolean trustAll = oidcConfig.defaultTenant.tls.getVerification().isPresent()
                ? oidcConfig.defaultTenant.tls.getVerification().get() == OidcCommonConfig.Tls.Verification.NONE
                : tlsConfig.trustAll;
        if (trustAll) {
            adapterConfig.setDisableTrustManager(true);
            adapterConfig.setAllowAnyHostname(true);
        }

        if (oidcConfig.defaultTenant.proxy.host.isPresent()) {
            adapterConfig.setProxyUrl(oidcConfig.defaultTenant.proxy.host.get() + ":" + oidcConfig.defaultTenant.proxy.port);
        }

        // create the authz-client (similar to org.keycloak.adapters.authorization.PolicyEnforcer)
        var deployment = KeycloakDeploymentBuilder.build(adapterConfig);
        Configuration configuration = new Configuration(adapterConfig.getAuthServerUrl(), adapterConfig.getRealm(), adapterConfig.getResource(), adapterConfig.getCredentials(), deployment.getClient());
        return AuthzClient.create(configuration, (requestParams, requestHeaders) -> {
            Map<String, String> formparams = new HashMap<>();
            ClientCredentialsProviderUtils.setClientCredentials(deployment, requestHeaders, formparams);
            for (Map.Entry<String, String> param : formparams.entrySet()) {
                requestParams.put(param.getKey(), Collections.singletonList(param.getValue()));
            }
        });
    }

    private Map<String, Object> getCredentials(OidcTenantConfig oidcConfig) {
        Map<String, Object> credentials = new HashMap<>();
        Optional<String> clientSecret = oidcConfig.getCredentials().getSecret();

        if (clientSecret.isPresent()) {
            credentials.put("secret", clientSecret.orElse(null));
        }

        return credentials;
    }
}

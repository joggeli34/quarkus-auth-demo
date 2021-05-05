package com.qumea;

import org.eclipse.microprofile.config.ConfigProvider;
import org.eclipse.microprofile.openapi.OASFilter;
import org.eclipse.microprofile.openapi.models.security.SecurityScheme;

public class SecuritySchemeFilter implements OASFilter {
    @Override
    public SecurityScheme filterSecurityScheme(final SecurityScheme securityScheme) {
        String url = ConfigProvider.getConfig().getValue("quarkus.oidc.auth-server-url", String.class);

        var implicitFlow = securityScheme.getFlows().getImplicit();

        implicitFlow.setAuthorizationUrl(url + "/protocol/openid-connect/auth");
        implicitFlow.setRefreshUrl(url + "/protocol/openid-connect/token");

        return securityScheme;
    }
}

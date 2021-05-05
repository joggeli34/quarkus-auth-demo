package com.qumea;

import org.eclipse.microprofile.jwt.JsonWebToken;
import org.jboss.resteasy.annotations.cache.NoCache;
import org.keycloak.authorization.client.AuthzClient;
import org.keycloak.authorization.client.representation.TokenIntrospectionResponse;
import org.keycloak.representations.idm.authorization.AuthorizationRequest;
import org.keycloak.representations.idm.authorization.AuthorizationResponse;
import org.keycloak.representations.idm.authorization.Permission;

import javax.inject.Inject;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;

@Path("/api/item")
public class ItemResource {
    @Inject
    AuthzClient authzClient;

    @Inject
    JsonWebToken accessToken;

    @GET
    @Path("{id}")
    @NoCache
    public String getItem(@PathParam("id") int id) {
        return "GET " + id;
    }

    @POST
    @Path("{id}")
    @NoCache
    public String postItem(@PathParam("id") int id) {
        return "POST " + id;
    }

    @GET
    @Path("{id}/test")
    @NoCache
    public String getTestItem(@PathParam("id") int id) {
        return "Test GET " + id;
    }

    @POST
    @Path("{id}/test")
    @NoCache
    public String postTestItem(@PathParam("id") int id) {
        return "Test POST " + id;
    }

    @GET
    @Path("")
    @NoCache
    public String getItemResources() {

        // create an authorization request
        AuthorizationRequest request = new AuthorizationRequest();

        // send the entitlement request to the server in order to
        // obtain an RPT with all permissions granted to the user
        AuthorizationResponse response = authzClient.authorization(accessToken.getRawToken()).authorize(request);
        String rpt = response.getToken();

        System.out.println("You got an RPT: " + rpt);

        // introspect the token
        TokenIntrospectionResponse requestingPartyToken = authzClient.protection().introspectRequestingPartyToken(rpt);

        System.out.println("Token status is: " + requestingPartyToken.getActive());
        System.out.println("Permissions granted by the server: ");

        for (Permission granted : requestingPartyToken.getPermissions()) {
            System.out.println(granted);
        }

        return rpt;
    }

}

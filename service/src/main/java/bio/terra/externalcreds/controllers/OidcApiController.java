package bio.terra.externalcreds.controllers;

import bio.terra.common.exception.UnauthorizedException;
import bio.terra.common.iam.BearerTokenParser;
import bio.terra.externalcreds.ExternalCredsException;
import bio.terra.externalcreds.generated.api.OidcApi;
import bio.terra.externalcreds.generated.model.LinkInfo;
import bio.terra.externalcreds.models.LinkedAccount;
import bio.terra.externalcreds.services.LinkedAccountService;
import bio.terra.externalcreds.services.ProviderService;
import bio.terra.externalcreds.services.SamService;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.OffsetDateTime;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import javax.servlet.http.HttpServletRequest;
import lombok.SneakyThrows;
import org.broadinstitute.dsde.workbench.client.sam.ApiException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;

@Controller
public class OidcApiController implements OidcApi {

  private final HttpServletRequest request;
  private final LinkedAccountService linkedAccountService;
  private final ObjectMapper mapper;
  private final ProviderService providerService;
  private final SamService samService;

  public OidcApiController(
      HttpServletRequest request,
      LinkedAccountService linkedAccountService,
      ObjectMapper mapper,
      ProviderService providerService,
      SamService samService) {
    this.request = request;
    this.linkedAccountService = linkedAccountService;
    this.mapper = mapper;
    this.providerService = providerService;
    this.samService = samService;
  }

  private String getUserIdFromSam() {
    try {
      var header = request.getHeader("authorization");
      if (header == null) throw new UnauthorizedException("User is not authorized");
      var accessToken = BearerTokenParser.parse(header);

      return samService.samUsersApi(accessToken).getUserStatusInfo().getUserSubjectId();
    } catch (ApiException e) {
      throw new ExternalCredsException(
          e,
          e.getCode() == HttpStatus.NOT_FOUND.value()
              ? HttpStatus.FORBIDDEN
              : HttpStatus.INTERNAL_SERVER_ERROR);
    }
  }

  private LinkInfo getLinkInfoFromLinkedAccount(LinkedAccount linkedAccount) {
    var expTime =
        OffsetDateTime.ofInstant(linkedAccount.getExpires().toInstant(), ZoneId.of("UTC"));
    return new LinkInfo()
        .externalUserId(linkedAccount.getExternalUserId())
        .expirationTimestamp(expTime);
  }

  @Override
  public ResponseEntity<List<String>> listProviders() {
    var providers = new ArrayList<>(providerService.getProviderList());
    Collections.sort(providers);

    return ResponseEntity.ok(providers);
  }

  @Override
  public ResponseEntity<LinkInfo> getLink(String provider) {
    var userId = getUserIdFromSam();
    var linkedAccount = linkedAccountService.getLinkedAccount(userId, provider);
    return linkedAccount
        .map(la -> ResponseEntity.ok(getLinkInfoFromLinkedAccount(la)))
        .orElseGet(() -> ResponseEntity.notFound().build());
  }

  // Because we're just processing String -> json string, there shouldn't be any conversion issue.
  @SneakyThrows(JsonProcessingException.class)
  @Override
  public ResponseEntity<String> getAuthUrl(
      String provider, List<String> scopes, String redirectUri, String state) {
    var authorizationUrl =
        providerService.getProviderAuthorizationUrl(
            provider, redirectUri, Set.copyOf(scopes), state);

    if (authorizationUrl == null) {
      return ResponseEntity.notFound().build();
    } else {
      // We explicitly run this through the mapper because otherwise it's treated as text/plain, and
      // not correctly quoted to be valid json.
      return ResponseEntity.ok(mapper.writeValueAsString(authorizationUrl));
    }
  }

  @Override
  public ResponseEntity<LinkInfo> createLink(
      String provider, List<String> scopes, String redirectUri, String state, String oauthcode) {
    var userId = getUserIdFromSam();

    var linkedAccountWithPassportAndVisas =
        providerService.createLink(
            provider, userId, oauthcode, redirectUri, Set.copyOf(scopes), state);

    return ResponseEntity.ok(
        getLinkInfoFromLinkedAccount(linkedAccountWithPassportAndVisas.getLinkedAccount()));
  }

  @Override
  public ResponseEntity<Void> deleteLink(String provider) {
    String userId = getUserIdFromSam();
    providerService.deleteLink(userId, provider);
    return ResponseEntity.ok().build();
  }
}

package bio.terra.externalcreds.controllers;

import bio.terra.externalcreds.auditLogging.AuditLogEvent;
import bio.terra.externalcreds.auditLogging.AuditLogEventType;
import bio.terra.externalcreds.auditLogging.AuditLogger;
import bio.terra.externalcreds.generated.api.OidcApi;
import bio.terra.externalcreds.generated.model.LinkInfo;
import bio.terra.externalcreds.generated.model.PassportProvider;
import bio.terra.externalcreds.generated.model.Provider;
import bio.terra.externalcreds.models.LinkedAccount;
import bio.terra.externalcreds.services.JwtUtils;
import bio.terra.externalcreds.services.LinkedAccountService;
import bio.terra.externalcreds.services.PassportProviderService;
import bio.terra.externalcreds.services.PassportService;
import bio.terra.externalcreds.services.TokenProviderService;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import java.sql.Timestamp;
import java.util.List;
import java.util.Optional;
import lombok.SneakyThrows;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;

@Controller
public record OidcApiController(
    AuditLogger auditLogger,
    HttpServletRequest request,
    JwtUtils jwtUtils,
    LinkedAccountService linkedAccountService,
    OauthApiController oauthApiController,
    ObjectMapper mapper,
    PassportService passportService,
    TokenProviderService tokenProviderService,
    PassportProviderService passportProviderService,
    ExternalCredsSamUserFactory samUserFactory)
    implements OidcApi {

  @Override
  public ResponseEntity<List<String>> listProviders() {
    return oauthApiController.listProviders();
  }

  @Override
  public ResponseEntity<LinkInfo> getLink(Provider provider) {
    return oauthApiController.getLink(provider);
  }

  @Override
  public ResponseEntity<String> getAuthUrl(Provider provider, String redirectUri) {
    return ResponseEntity.ok(
        jsonString(oauthApiController.getAuthorizationUrl(provider, redirectUri).getBody()));
  }

  @Override
  public ResponseEntity<LinkInfo> createLink(Provider provider, String state, String oauthcode) {
    return oauthApiController.createLink(provider, state, oauthcode);
  }

  @Override
  public ResponseEntity<Void> deleteLink(Provider provider) {
    return oauthApiController.deleteLink(provider);
  }

  @Override
  public ResponseEntity<String> getProviderPassport(PassportProvider passportProvider) {
    var samUser = samUserFactory.from(request);
    var provider = Provider.valueOf(passportProvider.name());
    var maybeLinkedAccount =
        linkedAccountService.getLinkedAccount(samUser.getSubjectId(), provider);
    var maybePassport = passportService.getPassport(samUser.getSubjectId(), provider);

    auditLogger.logEvent(
        new AuditLogEvent.Builder()
            .auditLogEventType(AuditLogEventType.GetPassport)
            .provider(provider)
            .userId(samUser.getSubjectId())
            .clientIP(request.getRemoteAddr())
            .externalUserId(maybeLinkedAccount.map(LinkedAccount::getExternalUserId))
            .build());

    var response =
        maybePassport.flatMap(
            passport -> {
              // passport should not be expired but if it is (due to some failure in ECM)
              // don't pass that failure on to the caller
              if (passport.getExpires().before(new Timestamp(System.currentTimeMillis()))) {
                return Optional.empty();
              } else {
                return Optional.of(passport.getJwt());
              }
            });
    return ResponseEntity.of(response);
  }

  /** Helper method to format a string as json. Otherwise it isn't quoted or escaped correctly. */
  @SneakyThrows(JsonProcessingException.class)
  private String jsonString(String s) {
    return mapper.writeValueAsString(s);
  }
}

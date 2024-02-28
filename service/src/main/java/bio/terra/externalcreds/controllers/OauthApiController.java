package bio.terra.externalcreds.controllers;

import bio.terra.externalcreds.ExternalCredsException;
import bio.terra.externalcreds.auditLogging.AuditLogEvent;
import bio.terra.externalcreds.auditLogging.AuditLogEventType;
import bio.terra.externalcreds.auditLogging.AuditLogger;
import bio.terra.externalcreds.controllers.OpenApiConverters.Output;
import bio.terra.externalcreds.generated.api.OauthApi;
import bio.terra.externalcreds.generated.model.LinkInfo;
import bio.terra.externalcreds.generated.model.Provider;
import bio.terra.externalcreds.services.*;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import java.util.Optional;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;

@Controller
public record OauthApiController(
    AuditLogger auditLogger,
    HttpServletRequest request,
    ObjectMapper mapper,
    LinkedAccountService linkedAccountService,
    ProviderService providerService,
    PassportProviderService passportProviderService,
    TokenProviderService tokenProviderService,
    FenceProviderService fenceProviderService,
    ExternalCredsSamUserFactory samUserFactory)
    implements OauthApi {

  @Override
  public ResponseEntity<LinkInfo> getLink(Provider provider) {
    var samUser = samUserFactory.from(request);

    var linkedAccount = linkedAccountService.getLinkedAccount(samUser.getSubjectId(), provider.toString());
    return ResponseEntity.of(linkedAccount.map(OpenApiConverters.Output::convert));

  }

  @Override
  public ResponseEntity<Void> deleteLink(Provider providerName) {
    var samUser = samUserFactory.from(request);
    var deletedLink = providerService.deleteLink(samUser.getSubjectId(), providerName.toString());

    auditLogger.logEvent(
        new AuditLogEvent.Builder()
            .auditLogEventType(AuditLogEventType.LinkDeleted)
            .providerName(providerName.toString())
            .userId(samUser.getSubjectId())
            .clientIP(request.getRemoteAddr())
            .externalUserId(deletedLink.getExternalUserId())
            .build());

    return ResponseEntity.ok().build();
  }

  @Override
  public ResponseEntity<String> getAuthorizationUrl(Provider providerName, String redirectUri) {
    var samUser = samUserFactory.from(request);

    var authorizationUrl =
        providerService.getProviderAuthorizationUrl(
            samUser.getSubjectId(), providerName.toString(), redirectUri);

    return ResponseEntity.of(authorizationUrl);
  }

  public ResponseEntity<String> getProviderAccessToken(Provider providerName) {
    var samUser = samUserFactory.from(request);

    var auditLogEventBuilder =
        new AuditLogEvent.Builder()
            .providerName(providerName.toString())
            .userId(samUser.getSubjectId())
            .clientIP(request.getRemoteAddr());

    var accessToken =
        tokenProviderService.getProviderAccessToken(
            samUser.getSubjectId(), providerName, auditLogEventBuilder);
    return ResponseEntity.of(accessToken);
  }

  @Override
  public ResponseEntity<LinkInfo> createLink(
      Provider providerName, String state, String oauthcode) {
    var samUser = samUserFactory.from(request);

    var auditLogEventBuilder =
        new AuditLogEvent.Builder()
            .providerName(providerName.toString())
            .userId(samUser.getSubjectId())
            .clientIP(request.getRemoteAddr());

    Optional<LinkInfo> linkInfo = Optional.empty();
    try {
      switch (providerName) {
        case RAS -> {
          var linkedAccountWithPassportAndVisas =
              passportProviderService.createLink(
                  providerName.toString(),
                  samUser.getSubjectId(),
                  oauthcode,
                  state,
                  auditLogEventBuilder);
          linkInfo =
              linkedAccountWithPassportAndVisas.map(
                  x -> OpenApiConverters.Output.convert(x.getLinkedAccount()));
        }
        case GITHUB -> {
          var linkedAccount =
              tokenProviderService.createLink(
                  providerName.toString(),
                  samUser.getSubjectId(),
                  oauthcode,
                  state,
                  auditLogEventBuilder);
          linkInfo = linkedAccount.map(Output::convert);
        }
      }
      return ResponseEntity.of(linkInfo);
    } catch (Exception e) {
      auditLogger.logEvent(
          auditLogEventBuilder.auditLogEventType(AuditLogEventType.LinkCreationFailed).build());
      throw e;
    }
  }
}

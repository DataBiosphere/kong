package bio.terra.externalcreds.controllers;

import bio.terra.common.exception.ForbiddenException;
import bio.terra.externalcreds.config.ExternalCredsConfig;
import bio.terra.externalcreds.generated.api.AdminApi;
import bio.terra.externalcreds.generated.model.AdminLinkInfo;
import bio.terra.externalcreds.generated.model.Provider;
import bio.terra.externalcreds.models.LinkedAccount;
import bio.terra.externalcreds.services.LinkedAccountService;
import bio.terra.externalcreds.services.PassportService;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import java.sql.Timestamp;
import java.util.List;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;

@Controller
public record AdminApiController(
    HttpServletRequest request,
    ObjectMapper mapper,
    LinkedAccountService linkedAccountService,
    PassportService passportService,
    ExternalCredsSamUserFactory samUserFactory,
    ExternalCredsConfig externalCredsConfig)
    implements AdminApi {

  @Override
  public ResponseEntity<Void> putLinkedAccountWithFakeToken(
      Provider provider, AdminLinkInfo adminLinkInfo) {
    requireAdmin();
    requireEraCommons(provider);
    var linkedAccount =
        new LinkedAccount.Builder()
            .isAuthenticated(true)
            .provider(provider)
            .userId(adminLinkInfo.getUserId())
            .refreshToken("fake-refresh-token")
            .externalUserId(adminLinkInfo.getLinkedExternalId())
            .expires(Timestamp.from(adminLinkInfo.getLinkExpireTime().toInstant()))
            .build();
    linkedAccountService.upsertLinkedAccount(linkedAccount);
    return ResponseEntity.noContent().build();
  }

  @Override
  public ResponseEntity<Void> adminDeleteLinkedAccount(Provider provider, String userId) {
    requireAdmin();
    var deleted = linkedAccountService.deleteLinkedAccount(userId, provider);
    if (!deleted) {
      return ResponseEntity.notFound().build();
    }
    return ResponseEntity.noContent().build();
  }

  @Override
  public ResponseEntity<List<AdminLinkInfo>> getActiveLinkedAccounts(Provider provider) {
    requireAdmin();
    var activeLinkedAccounts = linkedAccountService.getActiveLinkedAccounts(provider);
    return ResponseEntity.ok(
        activeLinkedAccounts.stream().map(OpenApiConverters.Output::convertAdmin).toList());
  }

  @Override
  public ResponseEntity<AdminLinkInfo> getLinkedAccountForExternalId(
      Provider provider, String externalId) {
    requireAdmin();
    var linkedAccount = linkedAccountService.getLinkedAccountForExternalId(provider, externalId);
    return ResponseEntity.of(linkedAccount.map(OpenApiConverters.Output::convertAdmin));
  }

  @Override
  public ResponseEntity<List<Object>> getVisas(
      Provider provider, String userId, String visaType, String issuer) {
    requireAdmin();
    return ResponseEntity.ok(
        passportService.getVisaClaims(provider, userId, issuer, visaType).stream()
            .map(mapper::valueToTree)
            .toList());
  }

  private void requireAdmin() {
    var samUser = samUserFactory.from(request);
    if (!externalCredsConfig.getAuthorizedAdmins().contains(samUser.getEmail())) {
      throw new ForbiddenException("Admin permissions required");
    }
  }

  private void requireEraCommons(Provider provider) {
    if (provider != Provider.ERA_COMMONS) {
      throw new ForbiddenException("Only eRA Commons is supported");
    }
  }
}

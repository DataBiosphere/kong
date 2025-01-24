package bio.terra.externalcreds.services;

import bio.terra.common.exception.BadRequestException;
import bio.terra.common.exception.NotFoundException;
import bio.terra.externalcreds.ExternalCredsException;
import bio.terra.externalcreds.auditLogging.AuditLogEvent;
import bio.terra.externalcreds.auditLogging.AuditLogEventType;
import bio.terra.externalcreds.auditLogging.AuditLogger;
import bio.terra.externalcreds.config.ExternalCredsConfig;
import bio.terra.externalcreds.generated.model.Provider;
import bio.terra.externalcreds.models.*;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.annotations.VisibleForTesting;
import java.sql.Timestamp;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;
import java.util.stream.Stream;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatusCode;
import org.springframework.security.oauth2.core.OAuth2AuthorizationException;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

@Service
@Slf4j
public class PassportProviderService extends ProviderService {
  private final PassportService passportService;
  private final JwtUtils jwtUtils;

  public PassportProviderService(
      ExternalCredsConfig externalCredsConfig,
      ProviderOAuthClientCache providerOAuthClientCache,
      ProviderTokenClientCache providerTokenClientCache,
      OAuth2Service oAuth2Service,
      LinkedAccountService linkedAccountService,
      FenceAccountKeyService fenceAccountKeyService,
      PassportService passportService,
      JwtUtils jwtUtils,
      AuditLogger auditLogger,
      ObjectMapper objectMapper) {
    super(
        externalCredsConfig,
        providerOAuthClientCache,
        providerTokenClientCache,
        oAuth2Service,
        linkedAccountService,
        fenceAccountKeyService,
        auditLogger,
        objectMapper);
    this.passportService = passportService;
    this.jwtUtils = jwtUtils;
  }

  public LinkedAccountWithPassportAndVisas createLink(
      Provider provider,
      String userId,
      String authorizationCode,
      String encodedState,
      AuditLogEvent.Builder auditLogEventBuilder) {

    var oAuth2State = validateOAuth2State(provider, userId, encodedState);
    var providerClient = providerOAuthClientCache.getProviderClient(provider);
    var providerInfo = externalCredsConfig.getProviderProperties(provider);
    try {
      var linkedAccount =
          createLinkedAccount(
              provider,
              userId,
              authorizationCode,
              oAuth2State.getRedirectUri(),
              new HashSet<>(providerInfo.getScopes()),
              encodedState,
              providerClient);
      var linkedAccountWithPassportAndVisas =
          linkedAccountService.upsertLinkedAccountWithPassportAndVisas(
              jwtUtils.enrichAccountWithPassportAndVisas(
                  linkedAccount.getLeft(), linkedAccount.getRight()));
      logLinkCreation(Optional.of(linkedAccountWithPassportAndVisas), auditLogEventBuilder);
      return linkedAccountWithPassportAndVisas;
    } catch (OAuth2AuthorizationException oauthEx) {
      logLinkCreation(Optional.empty(), auditLogEventBuilder);
      throw new BadRequestException(oauthEx);
    }
  }

  /**
   * It is important to invalidate an expired link when it has a passport because downstream systems
   * need to revoke authorizations that it grants. We don't need to actively do this when there are
   * no passports, we just stop serving access token requests.
   *
   * @return the number of links invalidated
   */
  public int invalidateExpiredLinkedAccountsWithPassports() {
    var expiredLinkedAccountsWithPassports =
        linkedAccountService.getExpiredLinkedAccountsWithPassports();
    expiredLinkedAccountsWithPassports.forEach(this::invalidateLinkedAccountAndRemovePassport);
    return expiredLinkedAccountsWithPassports.size();
  }

  private void logLinkCreation(
      Optional<LinkedAccountWithPassportAndVisas> linkedAccountWithPassportAndVisas,
      AuditLogEvent.Builder auditLogEventBuilder) {
    var passport =
        linkedAccountWithPassportAndVisas.flatMap(LinkedAccountWithPassportAndVisas::getPassport);
    var transactionClaim = passport.flatMap(p -> jwtUtils.getJwtTransactionClaim(p.getJwt()));
    auditLogger.logEvent(
        auditLogEventBuilder
            .externalUserId(
                linkedAccountWithPassportAndVisas.map(
                    l -> l.getLinkedAccount().getExternalUserId()))
            .auditLogEventType(
                linkedAccountWithPassportAndVisas
                    .map(x -> AuditLogEventType.LinkCreated)
                    .orElse(AuditLogEventType.LinkCreationFailed))
            .transactionClaim(transactionClaim)
            .build());
  }

  public int validateAccessTokenVisas() {
    var visaDetailsList = passportService.getUnvalidatedAccessTokenVisaDetails();

    var linkedAccountIdsToRefresh =
        visaDetailsList.stream()
            .flatMap(
                visaDetails ->
                    validateVisaWithProvider(visaDetails)
                        ? Stream.empty()
                        : Stream.of(visaDetails.getLinkedAccountId()))
            .distinct();

    linkedAccountIdsToRefresh.forEach(
        linkedAccountId -> {
          var linkedAccount = linkedAccountService.getLinkedAccount(linkedAccountId);
          try {
            linkedAccount.ifPresentOrElse(
                this::authAndRefreshPassport,
                () -> log.info("No linked account found when trying to validate passport."));
          } catch (Exception e) {
            log.info("Failed to refresh passport, will try again at the next interval.", e);
          }
        });

    return visaDetailsList.size();
  }

  /**
   * Get a new passport for each linked accounts with visas or passports expiring within
   * externalCredsConfig.getVisaAndPassportRefreshInterval time from now
   *
   * @return the number of linked accounts with expiring visas or passports
   */
  public int refreshExpiringPassports() {
    var refreshInterval = externalCredsConfig.getVisaAndPassportRefreshDuration();
    var expirationCutoff = new Timestamp(Instant.now().plus(refreshInterval).toEpochMilli());
    var expiringLinkedAccounts =
        linkedAccountService.getLinkedAccountsWithExpiringPassportsOrVisas(expirationCutoff);

    for (LinkedAccount linkedAccount : expiringLinkedAccounts) {
      try {
        authAndRefreshPassport(linkedAccount);
      } catch (Exception e) {
        log.info("Failed to refresh passport, will try again at the next interval.", e);
      }
    }

    return expiringLinkedAccounts.size();
  }

  @VisibleForTesting
  void authAndRefreshPassport(LinkedAccount linkedAccount) {
    if (linkedAccount.getExpires().toInstant().isBefore(Instant.now())) {
      invalidateLinkedAccountAndRemovePassport(linkedAccount);
    } else {
      try {
        var linkedAccountWithRefreshedPassport = getRefreshedPassportsAndVisas(linkedAccount);
        linkedAccountService.upsertLinkedAccountWithPassportAndVisas(
            linkedAccountWithRefreshedPassport);
        var transactionClaim =
            linkedAccountWithRefreshedPassport
                .getPassport()
                .flatMap(p -> jwtUtils.getJwtTransactionClaim(p.getJwt()));
        auditLogger.logEvent(
            new AuditLogEvent.Builder()
                .auditLogEventType(AuditLogEventType.LinkRefreshed)
                .provider(linkedAccount.getProvider())
                .userId(linkedAccount.getUserId())
                .externalUserId(linkedAccount.getExternalUserId())
                .transactionClaim(transactionClaim)
                .build());

      } catch (IllegalArgumentException iae) {
        throw new ExternalCredsException(
            String.format("Could not contact issuer for provider %s", linkedAccount.getProvider()),
            iae);
      } catch (OAuth2AuthorizationException oauthEx) {
        // if it looks like the refresh token will never work, delete the passport
        if (unrecoverableOAuth2ErrorCodes.contains(getRootOAuth2ErrorCode(oauthEx))) {
          log.info(
              String.format(
                  "Caught unrecoverable oauth2 error code refreshing passport for user id [%s].",
                  linkedAccount.getUserId()),
              oauthEx);
          if (linkedAccount.getId().isEmpty()) {
            throw new ExternalCredsException("linked account id missing");
          }
          invalidateLinkedAccountAndRemovePassport(linkedAccount);
        } else {
          // log and try again later
          throw new ExternalCredsException("Failed to refresh passport: ", oauthEx);
        }
      }
    }
  }

  private LinkedAccountWithPassportAndVisas getRefreshedPassportsAndVisas(
      LinkedAccount linkedAccount) {
    var clientRegistration =
        providerOAuthClientCache.getProviderClient(linkedAccount.getProvider());
    var accessTokenResponse =
        oAuth2Service.authorizeWithRefreshToken(
            clientRegistration,
            new OAuth2RefreshToken(linkedAccount.getRefreshToken(), null),
            Collections.emptySet());

    // save the linked account with the new refresh token and extracted passport
    var linkedAccountWithRefreshToken =
        Optional.ofNullable(accessTokenResponse.getRefreshToken())
            .map(
                refreshToken ->
                    linkedAccountService.upsertLinkedAccount(
                        linkedAccount.withRefreshToken(refreshToken.getTokenValue())))
            .orElse(linkedAccount);

    // update the passport and visas
    var userInfo =
        oAuth2Service.getUserInfo(clientRegistration, accessTokenResponse.getAccessToken());
    return jwtUtils.enrichAccountWithPassportAndVisas(linkedAccountWithRefreshToken, userInfo);
  }

  @VisibleForTesting
  boolean validateVisaWithProvider(VisaVerificationDetails visaDetails) {
    var providerProperties = externalCredsConfig.getProviderProperties(visaDetails.getProvider());
    if (providerProperties == null) {
      throw new NotFoundException(
          String.format("Provider %s not found", visaDetails.getProvider()));
    }

    var validationEndpoint =
        providerProperties
            .getValidationEndpoint()
            .orElseThrow(
                () ->
                    new NotFoundException(
                        String.format(
                            "Validation endpoint for provider %s not found",
                            visaDetails.getProvider())));

    var response =
        WebClient.create(validationEndpoint)
            .get()
            .uri(uriBuilder -> uriBuilder.queryParam("visa", visaDetails.getVisaJwt()).build())
            .retrieve();
    var responseBody =
        response
            .onStatus(HttpStatusCode::isError, clientResponse -> Mono.empty())
            .bodyToMono(String.class)
            .block(Duration.of(1000, ChronoUnit.MILLIS));

    log.info(
        "Got visa validation response.",
        Map.of(
            "linkedAccountId", visaDetails.getLinkedAccountId(),
            "providerName", visaDetails.getProvider().toString(),
            "validationResponse", Objects.requireNonNullElse(responseBody, "[null]")));

    var visaValid = "valid".equalsIgnoreCase(responseBody);

    if (visaValid) {
      passportService.updateVisaLastValidated(visaDetails.getVisaId());
    }
    return visaValid;
  }
}

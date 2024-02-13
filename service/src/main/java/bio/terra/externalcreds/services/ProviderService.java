package bio.terra.externalcreds.services;

import bio.terra.common.exception.BadRequestException;
import bio.terra.common.exception.NotFoundException;
import bio.terra.externalcreds.ExternalCredsException;
import bio.terra.externalcreds.auditLogging.AuditLogEvent;
import bio.terra.externalcreds.auditLogging.AuditLogEventType;
import bio.terra.externalcreds.auditLogging.AuditLogger;
import bio.terra.externalcreds.config.ExternalCredsConfig;
import bio.terra.externalcreds.config.ProviderProperties;
import bio.terra.externalcreds.generated.model.Provider;
import bio.terra.externalcreds.models.CannotDecodeOAuth2State;
import bio.terra.externalcreds.models.LinkedAccount;
import bio.terra.externalcreds.models.LinkedAccountWithPassportAndVisas;
import bio.terra.externalcreds.models.OAuth2State;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.security.SecureRandom;
import java.sql.Timestamp;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.tuple.ImmutablePair;
import org.springframework.http.HttpStatusCode;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.OAuth2AuthorizationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

@Service
@Slf4j
public class ProviderService {
  public final ExternalCredsConfig externalCredsConfig;
  public final ProviderClientCache providerClientCache;
  public final OAuth2Service oAuth2Service;
  public final LinkedAccountService linkedAccountService;
  public final AuditLogger auditLogger;
  public final SecureRandom secureRandom = new SecureRandom();
  public final ObjectMapper objectMapper;
  public static final Collection<String> unrecoverableOAuth2ErrorCodes =
      Set.of(
          OAuth2ErrorCodes.ACCESS_DENIED,
          OAuth2ErrorCodes.INSUFFICIENT_SCOPE,
          OAuth2ErrorCodes.INVALID_CLIENT,
          OAuth2ErrorCodes.INVALID_GRANT,
          OAuth2ErrorCodes.INVALID_REDIRECT_URI,
          OAuth2ErrorCodes.INVALID_REQUEST,
          OAuth2ErrorCodes.INVALID_SCOPE,
          OAuth2ErrorCodes.INVALID_TOKEN,
          OAuth2ErrorCodes.UNAUTHORIZED_CLIENT,
          OAuth2ErrorCodes.UNSUPPORTED_GRANT_TYPE,
          OAuth2ErrorCodes.UNSUPPORTED_RESPONSE_TYPE,
          OAuth2ErrorCodes.UNSUPPORTED_TOKEN_TYPE);

  public ProviderService(
      ExternalCredsConfig externalCredsConfig,
      ProviderClientCache providerClientCache,
      OAuth2Service oAuth2Service,
      LinkedAccountService linkedAccountService,
      AuditLogger auditLogger,
      ObjectMapper objectMapper) {
    this.externalCredsConfig = externalCredsConfig;
    this.providerClientCache = providerClientCache;
    this.oAuth2Service = oAuth2Service;
    this.linkedAccountService = linkedAccountService;
    this.auditLogger = auditLogger;
    this.objectMapper = objectMapper;
  }

  public Set<String> getProviderList() {
    return Collections.unmodifiableSet(externalCredsConfig.getProviders().keySet());
  }

  public Optional<String> getProviderAuthorizationUrl(
      String userId, Provider provider, String redirectUri) {
    return providerClientCache
        .getProviderClient(provider.toString())
        .map(
            providerClient -> {
              var providerInfo = externalCredsConfig.getProviders().get(provider.toString());

              validateRedirectUri(redirectUri, providerInfo);

              // oAuth2State is used to prevent CRSF attacks
              // see https://auth0.com/docs/secure/attack-protection/state-parameters
              // a random value is generated and stored here then validated in createLink below
              var oAuth2State =
                  new OAuth2State.Builder()
                      .provider(provider.toString())
                      .random(OAuth2State.generateRandomState(secureRandom))
                      .redirectUri(redirectUri)
                      .build();
              linkedAccountService.upsertOAuth2State(userId, oAuth2State);

              return oAuth2Service.getAuthorizationRequestUri(
                  providerClient,
                  redirectUri,
                  new HashSet<>(providerInfo.getScopes()),
                  oAuth2State.encode(objectMapper),
                  providerInfo.getAdditionalAuthorizationParameters());
            });
  }

  private void validateRedirectUri(String redirectUri, ProviderProperties providerInfo) {
    if (providerInfo.getAllowedRedirectUriPatterns().stream()
        .noneMatch(pattern -> pattern.matcher(redirectUri).matches())) {
      throw new BadRequestException("redirect uri not allowed");
    }
  }

  public OAuth2State validateOAuth2State(Provider provider, String userId, String encodedState) {
    try {
      OAuth2State oAuth2State = OAuth2State.decode(objectMapper, encodedState);
      if (!provider.toString().equals(oAuth2State.getProvider())) {
        throw new InvalidOAuth2State();
      }
      linkedAccountService.validateAndDeleteOAuth2State(userId, oAuth2State);
      return oAuth2State;
    } catch (CannotDecodeOAuth2State e) {
      throw new InvalidOAuth2State(e);
    }
  }

  protected ImmutablePair<LinkedAccount, OAuth2User> createLinkedAccount(
      Provider provider,
      String userId,
      String authorizationCode,
      String redirectUri,
      Set<String> scopes,
      String state,
      ClientRegistration providerClient) {
    var providerInfo = externalCredsConfig.getProviders().get(provider.toString());

    var tokenResponse =
        oAuth2Service.authorizationCodeExchange(
            providerClient,
            authorizationCode,
            redirectUri,
            scopes,
            state,
            providerInfo.getAdditionalAuthorizationParameters());

    var refreshToken = tokenResponse.getRefreshToken();
    if (refreshToken == null) {
      throw new ExternalCredsException(
          "cannot link account because authorization response did not contain refresh token");
    }

    var expires = new Timestamp(Instant.now().plus(providerInfo.getLinkLifespan()).toEpochMilli());

    var userInfo = oAuth2Service.getUserInfo(providerClient, tokenResponse.getAccessToken());

    String externalUserId = userInfo.getAttribute(providerInfo.getExternalIdClaim());
    if (externalUserId == null) {
      throw new ExternalCredsException(
          String.format(
              "user info from provider %s did not contain external id claim %s",
              provider, providerInfo.getExternalIdClaim()));
    }
    LinkedAccount linkedAccount =
        new LinkedAccount.Builder()
            .providerName(provider.toString())
            .userId(userId)
            .expires(expires)
            .externalUserId(externalUserId)
            .refreshToken(refreshToken.getTokenValue())
            .isAuthenticated(true)
            .build();
    return new ImmutablePair<>(linkedAccount, userInfo);
  }

  /**
   * Traverse causes for oauthEx until the cause is null or there is a cycle in the causes. Return
   * the last oauth2 error code found. This is needed because Spring likes to wrap
   * OAuth2AuthorizationExceptions with other OAuth2AuthorizationExceptions that have non-standard
   * error codes. We just want to handle standard error codes which should be in the root cause.
   */
  protected String getRootOAuth2ErrorCode(OAuth2AuthorizationException oauthEx) {
    var errorCode = oauthEx.getError().getErrorCode();
    Throwable currentThrowable = oauthEx.getCause();
    var visitedThrowables = new ArrayList<Throwable>();
    visitedThrowables.add(oauthEx);

    while (currentThrowable != null && !visitedThrowables.contains(currentThrowable)) {
      if (currentThrowable instanceof OAuth2AuthorizationException nestedOauthEx) {
        errorCode = nestedOauthEx.getError().getErrorCode();
      }
      visitedThrowables.add(currentThrowable);
      currentThrowable = currentThrowable.getCause();
    }

    return errorCode;
  }

  public LinkedAccount deleteLink(String userId, Provider provider) {
    var providerInfo = externalCredsConfig.getProviders().get(provider.toString());

    if (providerInfo == null) {
      throw new NotFoundException(String.format("Provider %s not found", provider));
    }

    var linkedAccount =
        linkedAccountService
            .getLinkedAccount(userId, provider)
            .orElseThrow(() -> new NotFoundException("Link not found for user"));

    revokeAccessToken(providerInfo, linkedAccount);

    linkedAccountService.deleteLinkedAccount(userId, provider);

    return linkedAccount;
  }

  protected void invalidateLinkedAccount(LinkedAccount linkedAccount) {
    auditLogger.logEvent(
        new AuditLogEvent.Builder()
            .auditLogEventType(AuditLogEventType.LinkExpired)
            .providerName(linkedAccount.getProviderName())
            .userId(linkedAccount.getUserId())
            .externalUserId(linkedAccount.getExternalUserId())
            .build());

    linkedAccountService.upsertLinkedAccountWithPassportAndVisas(
        new LinkedAccountWithPassportAndVisas.Builder()
            .linkedAccount(linkedAccount.withIsAuthenticated(false))
            .passport(Optional.empty()) // explicitly set to empty to be clear about intent
            .build());
  }

  private void revokeAccessToken(
      ProviderProperties providerProperties, LinkedAccount linkedAccount) {
    // Get the endpoint URL and insert the token
    String revokeEndpoint =
        String.format(providerProperties.getRevokeEndpoint(), linkedAccount.getRefreshToken());
    // Add authorization information and make request
    WebClient.ResponseSpec response =
        WebClient.create(revokeEndpoint)
            .post()
            .uri(
                uriBuilder ->
                    uriBuilder
                        .queryParam("client_id", providerProperties.getClientId())
                        .queryParam("client_secret", providerProperties.getClientSecret())
                        .build())
            .retrieve();

    String responseBody =
        response
            .onStatus(HttpStatusCode::isError, clientResponse -> Mono.empty())
            .bodyToMono(String.class)
            .block(Duration.of(1000, ChronoUnit.MILLIS));

    log.info(
        "Token revocation request for user [{}], provider [{}] returned with the result: [{}]",
        linkedAccount.getUserId(),
        linkedAccount.getProviderName(),
        responseBody);
  }
}

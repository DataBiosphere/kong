package bio.terra.externalcreds.services;

import bio.terra.externalcreds.config.ProviderConfig;
import java.util.Collections;
import java.util.Set;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.stereotype.Service;

@Service
@Slf4j
public class ProviderService {

  private final ProviderConfig providerConfig;
  private final ProviderClientCache providerClientCache;
  private final OAuth2Service oAuth2Service;

  public ProviderService(
      ProviderConfig providerConfig,
      ProviderClientCache providerClientCache,
      OAuth2Service oAuth2Service) {
    this.providerConfig = providerConfig;
    this.providerClientCache = providerClientCache;
    this.oAuth2Service = oAuth2Service;
  }

  public Set<String> getProviderList() {
    return Collections.unmodifiableSet(providerConfig.getServices().keySet());
  }

  public String getProviderAuthorizationUrl(
      String provider, String redirectUri, Set<String> scopes, String state) {
    ProviderConfig.ProviderInfo providerInfo = providerConfig.getServices().get(provider);
    if (providerInfo == null) {
      return null;
    }

    ClientRegistration providerClient = providerClientCache.getProviderClient(provider);

    return oAuth2Service.getAuthorizationRequestUri(
        providerClient,
        redirectUri,
        scopes,
        state,
        providerInfo.getAdditionalAuthorizationParameters());
  }

  public ProviderConfig.ProviderInfo getProviderInfo(String provider) {
    return providerConfig.getServices().get(provider);
  }
}

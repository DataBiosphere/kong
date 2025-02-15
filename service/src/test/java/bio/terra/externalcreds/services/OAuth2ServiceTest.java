package bio.terra.externalcreds.services;

import bio.terra.externalcreds.config.ExternalCredsConfig;
import bio.terra.externalcreds.config.ProviderProperties;
import bio.terra.externalcreds.generated.model.Provider;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.HashSet;
import java.util.Scanner;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.stereotype.Component;

@SpringBootApplication(scanBasePackages = {"bio.terra.externalcreds"})
@Component
public class OAuth2ServiceTest {

  @Autowired private ExternalCredsConfig externalCredsConfig;
  @Autowired private OAuth2Service oAuth2Service;
  @Autowired private ProviderOAuthClientCache providerOAuthClientCache;

  public static void main(String[] args) {
    new SpringApplicationBuilder(OAuth2ServiceTest.class)
        .profiles("human-readable-logging")
        .run(args)
        .getBean(OAuth2ServiceTest.class)
        .test();
  }

  /**
   * Test to run through the basics of the oauth flow. Must have local configs rendered. This is its
   * own application instead of a standard unit test because it requires user interaction to login
   * to the identity provider.
   */
  void test() {
    Provider provider = Provider.RAS;
    var providerClient = providerOAuthClientCache.getProviderClient(provider);

    var redirectUri = "http://localhost:9000/fence-callback";
    String state = null;
    ProviderProperties providerProperties = externalCredsConfig.getProviderProperties(provider);
    var scopes = new HashSet<>(providerProperties.getScopes());
    var authorizationParameters = providerProperties.getAdditionalAuthorizationParameters();

    // 1) test getAuthorizationRequestUri
    var authorizationRequestUri =
        oAuth2Service.getAuthorizationRequestUri(
            providerClient, redirectUri, scopes, state, authorizationParameters);

    System.out.println(
        "Open following url, after login the browser will be redirected to a url that does not exist, copy the 'code' parameter from the URL and paste below");
    System.out.println(authorizationRequestUri);
    System.out.print("Enter authorization code: ");
    var authCode = new Scanner(System.in, StandardCharsets.UTF_8).nextLine();

    // 2) test authorizationCodeExchange
    var oAuth2AccessTokenResponse =
        oAuth2Service.authorizationCodeExchange(
            providerClient, authCode, redirectUri, scopes, state, authorizationParameters);

    // 3) test authorizeWithRefreshToken
    // note that oAuth2AccessTokenResponse already has an access token but get another for testing
    var tokenResponse =
        oAuth2Service.authorizeWithRefreshToken(
            providerClient, oAuth2AccessTokenResponse.getRefreshToken(), Collections.emptySet());

    System.out.println(
        "refresh token:__________" + tokenResponse.getRefreshToken().getTokenValue());

    // 4) test getUserInfo
    var oAuth2User = oAuth2Service.getUserInfo(providerClient, tokenResponse.getAccessToken());

    // oAuth2User should have the user's passport and email address in the attributes
    System.out.println(oAuth2User.toString());
  }
}

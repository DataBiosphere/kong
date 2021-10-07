package bio.terra.externalcreds.services;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import bio.terra.common.exception.NotFoundException;
import bio.terra.externalcreds.BaseTest;
import bio.terra.externalcreds.ExternalCredsException;
import bio.terra.externalcreds.TestUtils;
import bio.terra.externalcreds.config.ExternalCredsConfig;
import bio.terra.externalcreds.dataAccess.GA4GHPassportDAO;
import bio.terra.externalcreds.dataAccess.GA4GHVisaDAO;
import bio.terra.externalcreds.dataAccess.LinkedAccountDAO;
import bio.terra.externalcreds.models.GA4GHVisa;
import bio.terra.externalcreds.models.LinkedAccount;
import bio.terra.externalcreds.models.LinkedAccountWithPassportAndVisas;
import bio.terra.externalcreds.models.TokenTypeEnum;
import bio.terra.externalcreds.models.VisaVerificationDetails;
import java.sql.Timestamp;
import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.mockserver.integration.ClientAndServer;
import org.mockserver.model.HttpRequest;
import org.mockserver.model.HttpResponse;
import org.mockserver.model.Parameter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.TestComponent;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.HttpStatus;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken.TokenType;
import org.springframework.security.oauth2.core.OAuth2AuthorizationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.web.client.HttpClientErrorException;

public class ProviderServiceTest extends BaseTest {

  @Nested
  @TestComponent
  class DeleteLink {

    @Autowired private ProviderService providerService;

    @MockBean private LinkedAccountService linkedAccountServiceMock;
    @MockBean private ExternalCredsConfig externalCredsConfigMock;

    @Test
    void testDeleteLinkedAccountAndRevokeToken() {
      testWithRevokeResponseCode(HttpStatus.OK);
    }

    @Test
    void testRevokeTokenError() {
      testWithRevokeResponseCode(HttpStatus.BAD_REQUEST);
    }

    @Test
    void testDeleteLinkProviderNotFound() {
      when(externalCredsConfigMock.getProviders()).thenReturn(Map.of());

      assertThrows(
          NotFoundException.class,
          () ->
              providerService.deleteLink(
                  UUID.randomUUID().toString(), UUID.randomUUID().toString()));
    }

    @Test
    void testDeleteLinkLinkNotFound() {
      var linkedAccount = TestUtils.createRandomLinkedAccount();

      when(externalCredsConfigMock.getProviders())
          .thenReturn(Map.of(linkedAccount.getProviderName(), TestUtils.createRandomProvider()));

      when(linkedAccountServiceMock.getLinkedAccount(
              linkedAccount.getUserId(), linkedAccount.getProviderName()))
          .thenReturn(Optional.empty());

      assertThrows(
          NotFoundException.class,
          () ->
              providerService.deleteLink(
                  linkedAccount.getUserId(), linkedAccount.getProviderName()));
    }

    private void testWithRevokeResponseCode(HttpStatus httpStatus) {
      var revocationPath = "/test/revoke/";
      var mockServerPort = 50555;
      var linkedAccount = TestUtils.createRandomLinkedAccount();

      var providerInfo =
          TestUtils.createRandomProvider()
              .setRevokeEndpoint(
                  "http://localhost:" + mockServerPort + revocationPath + "?token=%s");

      var expectedParameters =
          List.of(
              new Parameter("token", linkedAccount.getRefreshToken()),
              new Parameter("client_id", providerInfo.getClientId()),
              new Parameter("client_secret", providerInfo.getClientSecret()));

      when(externalCredsConfigMock.getProviders())
          .thenReturn(Map.of(linkedAccount.getProviderName(), providerInfo));

      when(linkedAccountServiceMock.getLinkedAccount(
              linkedAccount.getUserId(), linkedAccount.getProviderName()))
          .thenReturn(Optional.of(linkedAccount));
      when(linkedAccountServiceMock.deleteLinkedAccount(
              linkedAccount.getUserId(), linkedAccount.getProviderName()))
          .thenReturn(true);

      //  Mock the server response
      var mockServer = ClientAndServer.startClientAndServer(mockServerPort);
      try {
        mockServer
            .when(
                HttpRequest.request(revocationPath)
                    .withMethod("POST")
                    .withQueryStringParameters(expectedParameters))
            .respond(HttpResponse.response().withStatusCode(httpStatus.value()));

        providerService.deleteLink(linkedAccount.getUserId(), linkedAccount.getProviderName());
        verify(linkedAccountServiceMock)
            .deleteLinkedAccount(linkedAccount.getUserId(), linkedAccount.getProviderName());
      } finally {
        mockServer.stop();
      }
    }
  }

  @Nested
  @TestComponent
  class AuthAndRefreshPassport {

    @Autowired private ProviderService providerService;
    @Autowired private GA4GHPassportDAO passportDAO;
    @Autowired private LinkedAccountDAO linkedAccountDAO;
    @Autowired private GA4GHVisaDAO visaDAO;

    @MockBean private ExternalCredsConfig externalCredsConfigMock;
    @MockBean private ProviderClientCache providerClientCacheMock;
    @MockBean private OAuth2Service oAuth2ServiceMock;
    @MockBean private JwtUtils jwtUtilsMock;

    @Test
    void testExpiredLinkedAccountIsMarkedInvalid() {
      // save an expired linked account
      var expiredTimestamp = Timestamp.from(Instant.now().minus(Duration.ofMinutes(5)));
      var expiredLinkedAccount =
          linkedAccountDAO.upsertLinkedAccount(
              TestUtils.createRandomLinkedAccount().withExpires(expiredTimestamp));
      passportDAO.insertPassport(
          TestUtils.createRandomPassport().withLinkedAccountId(expiredLinkedAccount.getId()));

      // since the LinkedAccount itself is expired, it should be marked as invalid
      providerService.authAndRefreshPassport(expiredLinkedAccount);

      // check that the passport was deleted and the linked account was marked as invalid
      assertEmpty(
          passportDAO.getPassport(
              expiredLinkedAccount.getUserId(), expiredLinkedAccount.getProviderName()));
      var updatedLinkedAccount =
          linkedAccountDAO.getLinkedAccount(
              expiredLinkedAccount.getUserId(), expiredLinkedAccount.getProviderName());
      assertFalse(updatedLinkedAccount.get().isAuthenticated());
    }

    @Test
    void testInvalidVisaIssuer() {
      // save a non-expired linked account and nearly-expired passport
      var nonExpiredTimestamp = Timestamp.from(Instant.now().plus(Duration.ofMinutes(5)));
      var savedLinkedAccount =
          linkedAccountDAO.upsertLinkedAccount(
              TestUtils.createRandomLinkedAccount().withExpires(nonExpiredTimestamp));
      var savedPassport =
          passportDAO.insertPassport(
              TestUtils.createRandomPassport().withLinkedAccountId(savedLinkedAccount.getId()));
      // insert a visa with an invalid issuer
      visaDAO.insertVisa(
          TestUtils.createRandomVisa()
              .withPassportId(savedPassport.getId())
              .withIssuer("BadIssuer"));

      // mock configs
      when(externalCredsConfigMock.getProviders())
          .thenReturn(
              Map.of(
                  savedLinkedAccount.getProviderName(),
                  TestUtils.createRandomProvider().setIssuer("BadIssuer")));
      when(providerClientCacheMock.getProviderClient(savedLinkedAccount.getProviderName()))
          .thenThrow(new IllegalArgumentException());

      // check that an exception is thrown
      assertThrows(
          ExternalCredsException.class,
          () -> providerService.authAndRefreshPassport(savedLinkedAccount));
    }

    @Test
    void testOathBadRequestException() {

      // save a non-expired linked account and nearly-expired passport and visa
      var nonExpiredTimestamp = Timestamp.from(Instant.now().plus(Duration.ofMinutes(5)));
      var savedLinkedAccount =
          linkedAccountDAO.upsertLinkedAccount(
              TestUtils.createRandomLinkedAccount().withExpires(nonExpiredTimestamp));
      var savedPassport =
          passportDAO.insertPassport(
              TestUtils.createRandomPassport().withLinkedAccountId(savedLinkedAccount.getId()));
      visaDAO.insertVisa(TestUtils.createRandomVisa().withPassportId(savedPassport.getId()));

      mockProviderConfigs(savedLinkedAccount.getProviderName());

      // mock the ClientRegistration
      var clientRegistration = createClientRegistration(savedLinkedAccount.getProviderName());
      when(providerClientCacheMock.getProviderClient(savedLinkedAccount.getProviderName()))
          .thenReturn(Optional.of(clientRegistration));

      // mock the OAuth2AuthorizationException error thrown by the Oath2Service
      when(oAuth2ServiceMock.authorizeWithRefreshToken(
              clientRegistration,
              new OAuth2RefreshToken(savedLinkedAccount.getRefreshToken(), null)))
          .thenThrow(
              new OAuth2AuthorizationException(
                  new OAuth2Error(HttpStatus.BAD_REQUEST.toString()),
                  new HttpClientErrorException(HttpStatus.BAD_REQUEST)));

      // attempt to auth and refresh
      providerService.authAndRefreshPassport(savedLinkedAccount);

      // check that the passport was deleted and the linked account was marked as invalid
      assertEmpty(
          passportDAO.getPassport(
              savedLinkedAccount.getUserId(), savedLinkedAccount.getProviderName()));
      var updatedLinkedAccount =
          linkedAccountDAO.getLinkedAccount(
              savedLinkedAccount.getUserId(), savedLinkedAccount.getProviderName());
      assertFalse(updatedLinkedAccount.get().isAuthenticated());
    }

    @Test
    void testOtherOauthException() {

      // save a non-expired linked account and nearly-expired passport and visa
      var nonExpiredTimestamp = Timestamp.from(Instant.now().plus(Duration.ofMinutes(5)));
      var savedLinkedAccount =
          linkedAccountDAO.upsertLinkedAccount(
              TestUtils.createRandomLinkedAccount().withExpires(nonExpiredTimestamp));
      var savedPassport =
          passportDAO.insertPassport(
              TestUtils.createRandomPassport().withLinkedAccountId(savedLinkedAccount.getId()));
      visaDAO.insertVisa(TestUtils.createRandomVisa().withPassportId(savedPassport.getId()));

      mockProviderConfigs(savedLinkedAccount.getProviderName());

      // mock the ClientRegistration
      var clientRegistration = createClientRegistration(savedLinkedAccount.getProviderName());
      when(providerClientCacheMock.getProviderClient(savedLinkedAccount.getProviderName()))
          .thenReturn(Optional.of(clientRegistration));

      // mock the OAuth2AuthorizationException error thrown by the Oath2Service
      when(oAuth2ServiceMock.authorizeWithRefreshToken(
              clientRegistration,
              new OAuth2RefreshToken(savedLinkedAccount.getRefreshToken(), null)))
          .thenThrow(
              new OAuth2AuthorizationException(new OAuth2Error(HttpStatus.BAD_REQUEST.toString())));

      // check that the expected exception is thrown
      assertThrows(
          ExternalCredsException.class,
          () -> providerService.authAndRefreshPassport(savedLinkedAccount));
    }

    @Test
    void testSuccessfulAuthAndRefresh() {
      var updatedRefreshToken = "newRefreshToken";

      // save a non-expired linked account and nearly-expired passport and visa
      var nonExpiredTimestamp = Timestamp.from(Instant.now().plus(Duration.ofMinutes(5)));
      var savedLinkedAccount =
          linkedAccountDAO.upsertLinkedAccount(
              TestUtils.createRandomLinkedAccount().withExpires(nonExpiredTimestamp));
      var savedPassport =
          passportDAO.insertPassport(
              TestUtils.createRandomPassport().withLinkedAccountId(savedLinkedAccount.getId()));
      visaDAO.insertVisa(TestUtils.createRandomVisa().withPassportId(savedPassport.getId()));

      mockProviderConfigs(savedLinkedAccount.getProviderName());

      // mock the ClientRegistration
      var clientRegistration = createClientRegistration(savedLinkedAccount.getProviderName());
      when(providerClientCacheMock.getProviderClient(savedLinkedAccount.getProviderName()))
          .thenReturn(Optional.of(clientRegistration));

      // mock the OAuth2Authorization response
      var oAuth2TokenResponse =
          OAuth2AccessTokenResponse.withToken("tokenValue")
              .refreshToken(updatedRefreshToken)
              .tokenType(TokenType.BEARER)
              .build();
      when(oAuth2ServiceMock.authorizeWithRefreshToken(
              clientRegistration,
              new OAuth2RefreshToken(savedLinkedAccount.getRefreshToken(), null)))
          .thenReturn(oAuth2TokenResponse);

      // returning null here because it's passed to another mocked function and isn't worth mocking
      when(oAuth2ServiceMock.getUserInfo(eq(clientRegistration), Mockito.any())).thenReturn(null);

      // mock the LinkedAccountWithPassportAndVisas that would normally be read from a JWT
      var refreshedPassport =
          TestUtils.createRandomPassport().withLinkedAccountId(savedLinkedAccount.getId());
      var refreshedVisa = TestUtils.createRandomVisa();
      when(jwtUtilsMock.enrichAccountWithPassportAndVisas(
              eq(savedLinkedAccount.withRefreshToken(updatedRefreshToken)), Mockito.any()))
          .thenReturn(
              new LinkedAccountWithPassportAndVisas.Builder()
                  .linkedAccount(savedLinkedAccount.withRefreshToken(updatedRefreshToken))
                  .passport(refreshedPassport)
                  .visas(List.of(refreshedVisa))
                  .build());

      // attempt to auth and refresh
      providerService.authAndRefreshPassport(savedLinkedAccount);

      // check that the passport and visa were updated in the DB
      var actualUpdatedPassport =
          passportDAO
              .getPassport(savedLinkedAccount.getUserId(), savedLinkedAccount.getProviderName())
              .get();
      var actualUpdatedLinkedAccount =
          linkedAccountDAO.getLinkedAccount(
              savedLinkedAccount.getUserId(), savedLinkedAccount.getProviderName());
      var actualUpdatedVisas =
          visaDAO.listVisas(savedLinkedAccount.getUserId(), savedLinkedAccount.getProviderName());
      assertEquals(
          savedLinkedAccount.withRefreshToken(updatedRefreshToken),
          actualUpdatedLinkedAccount.get());
      assertEquals(refreshedPassport.withId(actualUpdatedPassport.getId()), actualUpdatedPassport);
      assertEquals(1, actualUpdatedVisas.size());
      assertEquals(
          refreshedVisa
              .withId(actualUpdatedVisas.get(0).getId())
              .withPassportId(actualUpdatedPassport.getId()),
          actualUpdatedVisas.get(0));
    }

    private void mockProviderConfigs(String providerName) {
      when(externalCredsConfigMock.getProviders())
          .thenReturn(Map.of(providerName, TestUtils.createRandomProvider()));
    }

    private ClientRegistration createClientRegistration(String providerName) {
      return ClientRegistration.withRegistrationId(providerName)
          .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
          .build();
    }
  }

  @Nested
  @TestComponent
  class RefreshExpiringPassports {
    @Autowired private GA4GHPassportDAO passportDAO;
    @Autowired private LinkedAccountDAO linkedAccountDAO;
    @Autowired private ProviderService providerService;

    @MockBean private ExternalCredsConfig externalCredsConfigMock;

    @Test
    void testOnlyExpiringPassportsAreRefreshed() {
      // insert two linked accounts, one with an expiring passport, one with non-expiring passport
      var ExpiringLinkedAccount = TestUtils.createRandomLinkedAccount();
      var savedExpiringLinkedAccount = linkedAccountDAO.upsertLinkedAccount(ExpiringLinkedAccount);
      var nonExpiringLinkedAccount = TestUtils.createRandomLinkedAccount();
      var savedNonExpiringLinkedAccount =
          linkedAccountDAO.upsertLinkedAccount(nonExpiringLinkedAccount);

      var expiringPassport =
          TestUtils.createRandomPassport()
              .withExpires(new Timestamp(Instant.now().toEpochMilli()))
              .withLinkedAccountId(savedExpiringLinkedAccount.getId());
      var notExpiringPassport =
          TestUtils.createRandomPassport()
              .withExpires(new Timestamp(Instant.now().plus(Duration.ofMinutes(60)).toEpochMilli()))
              .withLinkedAccountId(savedNonExpiringLinkedAccount.getId());
      passportDAO.insertPassport(expiringPassport);
      passportDAO.insertPassport(notExpiringPassport);

      // mock the configs
      when(externalCredsConfigMock.getVisaAndPassportRefreshDuration())
          .thenReturn(Duration.ofMinutes(30));

      // check that authAndRefreshPassport is called exactly once with the expiring linked account
      var providerServiceSpy = Mockito.spy(providerService);
      providerServiceSpy.refreshExpiringPassports();
      verify(providerServiceSpy).authAndRefreshPassport(any());
      verify(providerServiceSpy).authAndRefreshPassport(savedExpiringLinkedAccount);
    }
  }

  @Nested
  @TestComponent
  class ValidateVisaWithProvider {
    @Autowired private ProviderService providerService;
    @Autowired private LinkedAccountDAO linkedAccountDAO;

    @MockBean ExternalCredsConfig externalCredsConfigMock;

    @Test
    void testSuccessfullyValidatePassportWithProvider() {
      var visaVerificationDetails = TestUtils.createRandomVisaVerificationDetails();

      var mockServer =
          mockValidationEndpointConfigsAndResponse(
              visaVerificationDetails, HttpStatus.OK, "Valid");

      var responseBody = providerService.validateVisaWithProvider(visaVerificationDetails);
      assertEquals("Valid", responseBody);

      mockServer.stop();
    }

    @Test
    void testValidateInvalidVisaWithProvider() {
      var visaVerificationDetails = TestUtils.createRandomVisaVerificationDetails();

      var mockServer =
          mockValidationEndpointConfigsAndResponse(
              visaVerificationDetails, HttpStatus.BAD_REQUEST, "Invalid Passport");

      var responseBody = providerService.validateVisaWithProvider(visaVerificationDetails);
      assertEquals("Invalid Passport", responseBody);

      mockServer.stop();
    }

    @Test
    void testProviderPropertiesIsNull() {
      var fakeProviderName = "fakeProvider";
      // when(externalCredsConfigMock.getProviders().get(fakeProviderName)).thenReturn(null);
      when(externalCredsConfigMock.getProviders()).thenReturn(new HashMap<>());

      // TODO: actually call the method you're testing you boob!!!!
      //      assertThrows(
      //          NotFoundException.class,
      //          () -> providerService.validateVisaWithProvider());
    }

   // @Test
//    void testNoValidationEndpoint() {
//
//      // TODO: finish this, needs visa verification details
//      var fakeProviderName = "fakeProvider";
//      //var providerProperties = TestUtils.createRandomProviderWithoutRevokeEndpoint();
//
//      when(externalCredsConfigMock.getProviders())
//          .thenReturn(Map.of(fakeProviderName, providerProperties));
//
//      assertThrows(
//          NotFoundException.class,
//          () -> externalCredsConfigMock.getProviders().get(fakeProviderName));
//    }

    private ClientAndServer mockValidationEndpointConfigsAndResponse(
        VisaVerificationDetails visaVerificationDetails,
        HttpStatus mockedStatusCode,
        String mockedResponseBody) {
      var mockServerPort = 50555;
      var validationEndpoint = "/fake-validation-endpoint";

      when(externalCredsConfigMock.getProviders())
          .thenReturn(
              Map.of(
                  visaVerificationDetails.getProviderName(),
                  TestUtils.createRandomProvider()
                      .setValidationEndpoint(
                          "http://localhost:" + mockServerPort + validationEndpoint)));

      //  Mock the server response with 400 response code for invalid passport format
      var mockServer = ClientAndServer.startClientAndServer(mockServerPort);
      var expectedQueryStringParameters =
          List.of(new Parameter("visa", visaVerificationDetails.getVisaJwt()));
      mockServer
          .when(
              HttpRequest.request(validationEndpoint)
                  .withMethod("GET")
                  .withQueryStringParameters(expectedQueryStringParameters))
          .respond(
              HttpResponse.response()
                  .withStatusCode(mockedStatusCode.value())
                  .withBody(mockedResponseBody));

      return mockServer;
    }
  }

  @Nested
  @TestComponent
  class ValidatePassportsWithAccessTokenVisas {
    @Autowired private ProviderService providerService;
    @Autowired private LinkedAccountService linkedAccountService;

    @Test
    void testValidResponse() {
      var providerServiceSpy = spy(providerService);
      // insert a linkedAccount, passport and visa
      var visaNeedingVerification =
          TestUtils.createRandomVisa()
              .withTokenType(TokenTypeEnum.access_token)
              .withLastValidated(
                  new Timestamp(Instant.now().minus(Duration.ofDays(50)).toEpochMilli()));
      var savedLinkedAccountWithPassportAndVisa =
          linkedAccountService.upsertLinkedAccountWithPassportAndVisas(
              new LinkedAccountWithPassportAndVisas.Builder()
                  .linkedAccount(TestUtils.createRandomLinkedAccount())
                  .passport(TestUtils.createRandomPassport())
                  .visas(List.of(visaNeedingVerification))
                  .build());

      var expectedVisaDetails =
          buildVisaVerificationDetails(
              savedLinkedAccountWithPassportAndVisa.getLinkedAccount(), visaNeedingVerification);
      doReturn("Valid").when(providerServiceSpy).validateVisaWithProvider(expectedVisaDetails);

      // check that validatePassportWithProvider is called once and no exceptions are thrown
      providerServiceSpy.validateAccessTokenVisas();
      verify(providerServiceSpy).validateVisaWithProvider(any());
      verify(providerServiceSpy).validateVisaWithProvider(expectedVisaDetails);
    }

    @Test
    void testInvalidResponse() {
      var providerServiceSpy = spy(providerService);
      // insert a linkedAccount, passport and visa
      var visaNeedingVerification =
          TestUtils.createRandomVisa()
              .withTokenType(TokenTypeEnum.access_token)
              .withLastValidated(
                  new Timestamp(Instant.now().minus(Duration.ofDays(50)).toEpochMilli()));
      var savedLinkedAccountWithPassportAndVisa =
          linkedAccountService.upsertLinkedAccountWithPassportAndVisas(
              new LinkedAccountWithPassportAndVisas.Builder()
                  .linkedAccount(TestUtils.createRandomLinkedAccount())
                  .passport(TestUtils.createRandomPassport())
                  .visas(List.of(visaNeedingVerification))
                  .build());

      // mock the behavior of helper functions which already have their own tests
      var expectedPassportDetails =
          buildVisaVerificationDetails(
              savedLinkedAccountWithPassportAndVisa.getLinkedAccount(), visaNeedingVerification);
      doReturn("Invalid")
          .when(providerServiceSpy)
          .validateVisaWithProvider(expectedPassportDetails);
      doNothing()
          .when(providerServiceSpy)
          .authAndRefreshPassport(savedLinkedAccountWithPassportAndVisa.getLinkedAccount());

      // check that validatePassportWithProvider is called once and no exceptions are thrown
      providerServiceSpy.validateAccessTokenVisas();
      verify(providerServiceSpy).validateVisaWithProvider(any());
      verify(providerServiceSpy).validateVisaWithProvider(expectedPassportDetails);

      // check that authAndRefreshPassport was also called once
      verify(providerServiceSpy)
          .authAndRefreshPassport(savedLinkedAccountWithPassportAndVisa.getLinkedAccount());
    }
  }

  private VisaVerificationDetails buildVisaVerificationDetails(
      LinkedAccount savedLinkedAccount, GA4GHVisa visa) {
    return new VisaVerificationDetails.Builder()
        .linkedAccountId(savedLinkedAccount.getId().get())
        .visaJwt(visa.getJwt())
        .providerName(savedLinkedAccount.getProviderName())
        .build();
  }

  //  private VisaVerificationDetails createVisaVerificationDetails(GA4GHVisa visa,
  // LinkedAccountService linkedAccountService) {
  //    var savedLinkedAccountWithPassportAndVisa =
  //        linkedAccountService.upsertLinkedAccountWithPassportAndVisas(
  //            new LinkedAccountWithPassportAndVisas.Builder()
  //                .linkedAccount(TestUtils.createRandomLinkedAccount())
  //                .passport(TestUtils.createRandomPassport())
  //                .visas(List.of(visa))
  //                .build());
  //
  //    return
  // buildVisaVerificationDetails(savedLinkedAccountWithPassportAndVisa.getLinkedAccount(),
  // savedLinkedAccountWithPassportAndVisa.);
  //  }
}

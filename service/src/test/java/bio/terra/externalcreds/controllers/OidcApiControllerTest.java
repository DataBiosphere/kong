package bio.terra.externalcreds.controllers;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import bio.terra.common.exception.BadRequestException;
import bio.terra.common.exception.NotFoundException;
import bio.terra.common.iam.BearerToken;
import bio.terra.common.iam.SamUser;
import bio.terra.externalcreds.BaseTest;
import bio.terra.externalcreds.ExternalCredsException;
import bio.terra.externalcreds.TestUtils;
import bio.terra.externalcreds.auditLogging.AuditLogEvent;
import bio.terra.externalcreds.auditLogging.AuditLogEventType;
import bio.terra.externalcreds.auditLogging.AuditLogger;
import bio.terra.externalcreds.generated.model.Provider;
import bio.terra.externalcreds.models.LinkedAccount;
import bio.terra.externalcreds.models.LinkedAccount.Builder;
import bio.terra.externalcreds.models.LinkedAccountWithPassportAndVisas;
import bio.terra.externalcreds.services.LinkedAccountService;
import bio.terra.externalcreds.services.PassportProviderService;
import bio.terra.externalcreds.services.PassportService;
import bio.terra.externalcreds.services.ProviderService;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import java.sql.Timestamp;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.util.LinkedMultiValueMap;

@AutoConfigureMockMvc
class OidcApiControllerTest extends BaseTest {

  @Autowired private ObjectMapper mapper;

  @Autowired private MockMvc mvc;

  @MockBean private LinkedAccountService linkedAccountServiceMock;

  @MockBean
  @Qualifier("providerService")
  private ProviderService providerServiceMock;

  @MockBean
  @Qualifier("passportProviderService")
  private PassportProviderService passportProviderServiceMock;

  @MockBean private ExternalCredsSamUserFactory samUserFactoryMock;
  @MockBean private PassportService passportServiceMock;
  @MockBean private AuditLogger auditLoggerMock;
  private Provider provider = Provider.RAS;

  @Test
  void testListProviders() throws Exception {
    when(providerServiceMock.getProviderList())
        .thenReturn(Set.of("fake-provider2", "fake-provider1"));

    mvc.perform(get("/api/oidc/v1/providers"))
        .andExpect(content().json("""
            ["fake-provider1","fake-provider2"]"""));
  }

  @Nested
  class GetAuthUrl {

    @Test
    void testGetAuthUrl() throws Exception {
      var userId = "fakeUser";
      var accessToken = "fakeAccessToken";
      var result = "https://test/authorization/uri";
      var redirectUri = "fakeuri";

      mockSamUser(userId, accessToken);

      when(providerServiceMock.getProviderAuthorizationUrl(userId, provider, redirectUri, null))
          .thenReturn(result);

      var queryParams = new LinkedMultiValueMap<String, String>();
      queryParams.add("redirectUri", redirectUri);
      mvc.perform(
              get("/api/oidc/v1/{provider}/authorization-url", provider)
                  .header("authorization", "Bearer " + accessToken)
                  .queryParams(queryParams))
          .andExpect(content().json("\"" + result + "\""));
    }

    @Test
    void testGetAuthUrlBadRequest() throws Exception {
      var userId = "fakeUser";
      var accessToken = "fakeAccessToken";
      var redirectUri = "fakeuri";

      mockSamUser(userId, accessToken);

      when(providerServiceMock.getProviderAuthorizationUrl(userId, provider, redirectUri, null))
          .thenThrow(new BadRequestException("Invalid redirectUri"));

      var queryParams = new LinkedMultiValueMap<String, String>();
      queryParams.add("redirectUri", redirectUri);
      mvc.perform(
              get("/api/oidc/v1/{provider}/authorization-url", provider)
                  .header("authorization", "Bearer " + accessToken)
                  .queryParams(queryParams))
          .andExpect(status().isBadRequest());
    }
  }

  @Nested
  class GetLink {

    @Test
    void testGetLink() throws Exception {
      var accessToken = "testToken";
      var inputLinkedAccount = TestUtils.createRandomLinkedAccount();

      mockSamUser(inputLinkedAccount.getUserId(), accessToken);

      when(linkedAccountServiceMock.getLinkedAccount(
              inputLinkedAccount.getUserId(), inputLinkedAccount.getProvider()))
          .thenReturn(Optional.of(inputLinkedAccount));

      mvc.perform(
              get("/api/oidc/v1/" + inputLinkedAccount.getProvider().toString())
                  .header("authorization", "Bearer " + accessToken))
          .andExpect(
              content()
                  .json(
                      mapper.writeValueAsString(
                          OpenApiConverters.Output.convert(inputLinkedAccount))));
    }

    @Test
    void testEnforcesCaseSensitivity() throws Exception {
      var accessToken = "testToken";
      var inputLinkedAccount = TestUtils.createRandomPassportLinkedAccount();

      mockSamUser(inputLinkedAccount.getUserId(), accessToken);

      when(linkedAccountServiceMock.getLinkedAccount(
              inputLinkedAccount.getUserId(), inputLinkedAccount.getProvider()))
          .thenReturn(Optional.of(inputLinkedAccount));

      mvc.perform(get("/api/oidc/v1/" + "RaS").header("authorization", "Bearer " + accessToken))
          .andExpect(
              content()
                  .json(
                      mapper.writeValueAsString(
                          OpenApiConverters.Output.convert(inputLinkedAccount))));
    }

    @Test
    void testGetLink404() throws Exception {
      var userId = "non-existent-user";
      var accessToken = "testToken";

      mockSamUser(userId, accessToken);

      mvc.perform(get("/api/oidc/v1/" + provider).header("authorization", "Bearer " + accessToken))
          .andExpect(status().isNotFound());
    }
  }

  @Nested
  class CreateLink {

    @Test
    void testCreatesLinkSuccessfully() throws Exception {
      var accessToken = "testToken";
      var inputLinkedAccount = TestUtils.createRandomPassportLinkedAccount();

      var state = UUID.randomUUID().toString();
      var oauthcode = UUID.randomUUID().toString();

      mockSamUser(inputLinkedAccount.getUserId(), accessToken);

      var linkedAccountWithPassportAndVisas =
          new LinkedAccountWithPassportAndVisas.Builder()
              .linkedAccount(inputLinkedAccount)
              .passport(TestUtils.createRandomPassport())
              .build();
      when(passportProviderServiceMock.createLink(
              eq(inputLinkedAccount.getProvider()),
              eq(inputLinkedAccount.getUserId()),
              eq(oauthcode),
              eq(state),
              any(AuditLogEvent.Builder.class)))
          .thenReturn(linkedAccountWithPassportAndVisas);

      mvc.perform(
              post("/api/oidc/v1/{provider}/oauthcode", inputLinkedAccount.getProvider().toString())
                  .header("authorization", "Bearer " + accessToken)
                  .param("state", state)
                  .param("oauthcode", oauthcode))
          .andExpect(status().isOk())
          .andExpect(
              content()
                  .json(
                      mapper.writeValueAsString(
                          OpenApiConverters.Output.convert(inputLinkedAccount))));
    }

    @Test
    void testExceptionIsLogged() throws Exception {
      var accessToken = "testToken";

      var userId = "userId";
      mockSamUser(userId, accessToken);

      when(passportProviderServiceMock.createLink(any(), any(), any(), any(), any()))
          .thenThrow(new ExternalCredsException("This is a drill!"));

      // check that an internal server error code is returned
      mvc.perform(
              post("/api/oidc/v1/{provider}/oauthcode", provider)
                  .header("authorization", "Bearer " + accessToken)
                  .param("scopes", "foo")
                  .param("redirectUri", "redirectUri")
                  .param("state", "state")
                  .param("oauthcode", "oauthcode"))
          .andExpect(status().isInternalServerError());

      // check that a log was recorded
      verify(auditLoggerMock)
          .logEvent(
              new AuditLogEvent.Builder()
                  .auditLogEventType(AuditLogEventType.LinkCreationFailed)
                  .provider(provider)
                  .userId(userId)
                  .clientIP("127.0.0.1")
                  .build());
    }
  }

  @Nested
  class DeleteLink {

    @Test
    void testDeleteLink() throws Exception {
      var accessToken = "testToken";
      var userId = UUID.randomUUID().toString();
      var externalId = UUID.randomUUID().toString();
      mockSamUser(userId, accessToken);

      when(providerServiceMock.deleteLink(userId, provider))
          .thenReturn(
              new Builder()
                  .provider(provider)
                  .userId(userId)
                  .externalUserId(externalId)
                  .expires(new Timestamp(0))
                  .isAuthenticated(true)
                  .refreshToken("")
                  .build());

      mvc.perform(
              delete("/api/oidc/v1/{provider}", provider)
                  .header("authorization", "Bearer " + accessToken))
          .andExpect(status().isOk());

      verify(providerServiceMock).deleteLink(userId, provider);

      // check that a log was recorded
      verify(auditLoggerMock)
          .logEvent(
              new AuditLogEvent.Builder()
                  .auditLogEventType(AuditLogEventType.LinkDeleted)
                  .provider(provider)
                  .userId(userId)
                  .clientIP("127.0.0.1")
                  .externalUserId(externalId)
                  .build());
    }

    @Test
    void testDeleteLink404() throws Exception {
      var accessToken = "testToken";
      var userId = UUID.randomUUID().toString();
      mockSamUser(userId, accessToken);

      doThrow(new NotFoundException("not found"))
          .when(providerServiceMock)
          .deleteLink(userId, provider);

      mvc.perform(
              delete("/api/oidc/v1/{provider}", provider)
                  .header("authorization", "Bearer " + accessToken))
          .andExpect(status().isNotFound());
    }
  }

  @Nested
  class GetProviderPassport {

    @Test
    void testGetProviderPassport() throws Exception {
      var accessToken = "testToken";
      var userId = UUID.randomUUID().toString();
      var externalUserId = UUID.randomUUID().toString();
      var passport =
          TestUtils.createRandomPassport()
              .withExpires(new Timestamp(System.currentTimeMillis() + 1000));

      mockSamUser(userId, accessToken);

      when(linkedAccountServiceMock.getLinkedAccount(userId, provider))
          .thenReturn(
              Optional.of(
                  new LinkedAccount.Builder()
                      .provider(provider)
                      .userId(userId)
                      .externalUserId(externalUserId)
                      .refreshToken("")
                      .expires(new Timestamp(0))
                      .isAuthenticated(true)
                      .build()));
      when(passportServiceMock.getPassport(userId, provider)).thenReturn(Optional.of(passport));

      mvc.perform(
              get("/api/oidc/v1/{provider}/passport", provider)
                  .header("authorization", "Bearer " + accessToken))
          .andExpect(status().isOk())
          .andExpect(content().string(passport.getJwt()));

      // check that a log was recorded
      verify(auditLoggerMock)
          .logEvent(
              new AuditLogEvent.Builder()
                  .auditLogEventType(AuditLogEventType.GetPassport)
                  .provider(provider)
                  .userId(userId)
                  .clientIP("127.0.0.1")
                  .externalUserId(externalUserId)
                  .build());
    }

    @Test
    void testGetProviderPassportDoesNotReturnExpired() throws Exception {
      var accessToken = "testToken";
      var userId = UUID.randomUUID().toString();
      var passport =
          TestUtils.createRandomPassport()
              .withExpires(new Timestamp(System.currentTimeMillis() - 1000));

      mockSamUser(userId, accessToken);

      when(passportServiceMock.getPassport(userId, provider)).thenReturn(Optional.of(passport));

      mvc.perform(
              get("/api/oidc/v1/{provider}/passport", provider)
                  .header("authorization", "Bearer " + accessToken))
          .andExpect(status().isNotFound());
    }

    @Test
    void testGetProviderPassport404() throws Exception {
      var accessToken = "testToken";
      var userId = UUID.randomUUID().toString();

      mockSamUser(userId, accessToken);

      mvc.perform(
              get("/api/oidc/v1/{provider}/passport", provider)
                  .header("authorization", "Bearer " + accessToken))
          .andExpect(status().isNotFound());
    }
  }

  private void mockSamUser(String userId, String accessToken) {
    when(samUserFactoryMock.from(any(HttpServletRequest.class)))
        .thenReturn(new SamUser("email", userId, new BearerToken(accessToken)));
  }
}

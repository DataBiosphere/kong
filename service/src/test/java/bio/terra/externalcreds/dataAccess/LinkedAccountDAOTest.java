package bio.terra.externalcreds.dataAccess;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;

import bio.terra.externalcreds.BaseTest;
import bio.terra.externalcreds.TestUtils;
import bio.terra.externalcreds.config.ExternalCredsConfig;
import bio.terra.externalcreds.config.ProviderProperties;
import bio.terra.externalcreds.generated.model.Provider;
import bio.terra.externalcreds.models.GA4GHPassport;
import java.sql.Timestamp;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.mock.mockito.MockBean;

class LinkedAccountDAOTest extends BaseTest {

  @Autowired private LinkedAccountDAO linkedAccountDAO;
  @Autowired private GA4GHPassportDAO passportDAO;
  @Autowired private GA4GHVisaDAO visaDAO;
  @MockBean private ExternalCredsConfig externalCredsConfig;

  @BeforeEach
  void setUp() {
    when(externalCredsConfig.getProviderProperties(Provider.FENCE))
        .thenReturn(ProviderProperties.create().setLinkLifespan(Duration.ofDays(30)));
  }

  @Test
  void testAllProvidersEnum() {
    for (Provider provider : Provider.values()) {
      // Tests if the provider enum in the DB values agrees with the provider enum in code
      // If there's a disagreement, an exception will be thrown
      linkedAccountDAO.getLinkedAccount("", provider);
    }
  }

  @Test
  void testGetMissingLinkedAccount() {
    var shouldBeEmpty = linkedAccountDAO.getLinkedAccount("", Provider.GITHUB);
    assertEmpty(shouldBeEmpty);
  }

  @Test
  void testGetLinkedAccountById() {
    var linkedAccount = TestUtils.createRandomLinkedAccount();
    var savedLinkedAccount = linkedAccountDAO.upsertLinkedAccount(linkedAccount);
    var loadedLinkedAccount = linkedAccountDAO.getLinkedAccount(savedLinkedAccount.getId().get());

    // test that retrieved account matches saved account
    assertEquals(
        Optional.of(savedLinkedAccount.withId(loadedLinkedAccount.get().getId())),
        loadedLinkedAccount);
  }

  @Test
  void testInsertAndGetLinkedAccount() {
    var linkedAccount = TestUtils.createRandomLinkedAccount();
    var savedLinkedAccount = linkedAccountDAO.upsertLinkedAccount(linkedAccount);
    assertTrue(savedLinkedAccount.getId().isPresent());
    assertEquals(linkedAccount.withId(savedLinkedAccount.getId()), savedLinkedAccount);

    var loadedLinkedAccount =
        linkedAccountDAO.getLinkedAccount(linkedAccount.getUserId(), linkedAccount.getProvider());
    assertEquals(Optional.of(savedLinkedAccount), loadedLinkedAccount);
  }

  @Test
  void testUpsertUpdatedLinkedAccount() {
    var linkedAccount = TestUtils.createRandomLinkedAccount();
    var createdLinkedAccount = linkedAccountDAO.upsertLinkedAccount(linkedAccount);

    var updatedLinkedAccount =
        linkedAccountDAO.upsertLinkedAccount(
            linkedAccount
                .withRefreshToken("different_refresh")
                .withExpires(new Timestamp(200))
                .withExternalUserId(UUID.randomUUID().toString()));

    assertEquals(createdLinkedAccount.getId(), updatedLinkedAccount.getId());
    assertNotEquals(createdLinkedAccount.getRefreshToken(), updatedLinkedAccount.getRefreshToken());
    assertNotEquals(
        createdLinkedAccount.getExternalUserId(), updatedLinkedAccount.getExternalUserId());
    assertNotEquals(createdLinkedAccount.getExpires(), updatedLinkedAccount.getExpires());

    var loadedLinkedAccount =
        linkedAccountDAO.getLinkedAccount(linkedAccount.getUserId(), linkedAccount.getProvider());
    assertEquals(Optional.of(updatedLinkedAccount), loadedLinkedAccount);
  }

  @Nested
  class DeleteLinkedAccount {

    @Test
    void testDeleteLinkedAccountIfExists() {
      var createdLinkedAccount =
          linkedAccountDAO.upsertLinkedAccount(TestUtils.createRandomLinkedAccount());
      var deletionSucceeded =
          linkedAccountDAO.deleteLinkedAccountIfExists(
              createdLinkedAccount.getUserId(), createdLinkedAccount.getProvider());
      assertTrue(deletionSucceeded);
      assertEmpty(
          linkedAccountDAO.getLinkedAccount(
              createdLinkedAccount.getUserId(), createdLinkedAccount.getProvider()));
    }

    @Test
    void testDeleteNonexistentLinkedAccount() {
      var userId = UUID.randomUUID().toString();
      var deletionSucceeded = linkedAccountDAO.deleteLinkedAccountIfExists(userId, Provider.GITHUB);
      assertEmpty(linkedAccountDAO.getLinkedAccount(userId, Provider.GITHUB));
      assertFalse(deletionSucceeded);
    }

    @Test
    void testAlsoDeletesPassport() {
      var savedLinkedAccount =
          linkedAccountDAO.upsertLinkedAccount(TestUtils.createRandomPassportLinkedAccount());
      assertPresent(savedLinkedAccount.getId());
      var passport =
          new GA4GHPassport.Builder()
              .linkedAccountId(savedLinkedAccount.getId())
              .expires(new Timestamp(100))
              .jwt("jwt")
              .jwtId(UUID.randomUUID().toString())
              .build();
      passportDAO.insertPassport(passport);
      linkedAccountDAO.deleteLinkedAccountIfExists(
          savedLinkedAccount.getUserId(), savedLinkedAccount.getProvider());
      assertEmpty(passportDAO.getPassport(savedLinkedAccount.getUserId(), Provider.RAS));
    }
  }

  @Nested
  class GetLinkedAccountsWithExpiringPassportsOrVisas {

    private final Timestamp testExpirationCutoff =
        new Timestamp(Instant.now().plus(Duration.ofMinutes(15)).toEpochMilli());
    private final Timestamp nonExpiringTimestamp =
        new Timestamp(Instant.now().plus(Duration.ofMinutes(30)).toEpochMilli());

    @Test
    void testGetsOnlyExpiringLinkedAccounts() {
      // Create a linked account with a not-nearly-expired passport and visa
      var linkedAccount = TestUtils.createRandomPassportLinkedAccount();
      var passport = TestUtils.createRandomPassport().withExpires(nonExpiringTimestamp);
      var visa = TestUtils.createRandomVisa().withExpires(nonExpiringTimestamp);

      var savedLinkedAccount = linkedAccountDAO.upsertLinkedAccount(linkedAccount);
      var savedPassport =
          passportDAO.insertPassport(passport.withLinkedAccountId(savedLinkedAccount.getId()));
      visaDAO.insertVisa(visa.withPassportId(savedPassport.getId()));

      // Create a linked account with an expiring passport and visa
      var expiringLinkedAccount = TestUtils.createRandomLinkedAccount();
      var expiringPassport = TestUtils.createRandomPassport();
      var expiringVisa = TestUtils.createRandomVisa();

      var savedExpiredLinkedAccount = linkedAccountDAO.upsertLinkedAccount(expiringLinkedAccount);
      var savedExpiredPassport =
          passportDAO.insertPassport(
              expiringPassport.withLinkedAccountId(savedExpiredLinkedAccount.getId()));
      visaDAO.insertVisa(expiringVisa.withPassportId(savedExpiredPassport.getId()));

      // Assert that only the expiring linked account is returned
      assertEquals(
          List.of(savedExpiredLinkedAccount),
          linkedAccountDAO.getLinkedAccountsWithExpiringPassportsOrVisas(testExpirationCutoff));
    }

    @Test
    void testGetsLinkedAccountWithNoVisas() {
      // Create a linked account with an expiring passport but no visas
      var linkedAccount = TestUtils.createRandomPassportLinkedAccount();
      var expiringPassport = TestUtils.createRandomPassport();
      var savedLinkedAccount = linkedAccountDAO.upsertLinkedAccount(linkedAccount);
      passportDAO.insertPassport(expiringPassport.withLinkedAccountId(savedLinkedAccount.getId()));

      // Assert that the linked account is returned
      assertEquals(
          List.of(savedLinkedAccount),
          linkedAccountDAO.getLinkedAccountsWithExpiringPassportsOrVisas(testExpirationCutoff));
    }

    @Test
    void testGetsLinkedAccountWithNonExpiredPassportAndExpiredVisa() {
      // Create a linked account with a non-expired passport and an expired visa
      var linkedAccount = TestUtils.createRandomPassportLinkedAccount();
      var passport = TestUtils.createRandomPassport().withExpires(nonExpiringTimestamp);
      var expiringVisa = TestUtils.createRandomVisa();

      var savedLinkedAccount = linkedAccountDAO.upsertLinkedAccount(linkedAccount);
      var savedPassport =
          passportDAO.insertPassport(passport.withLinkedAccountId(savedLinkedAccount.getId()));
      visaDAO.insertVisa(expiringVisa.withPassportId(savedPassport.getId()));

      // Assert that the linked account is returned
      assertEquals(
          List.of(savedLinkedAccount),
          linkedAccountDAO.getLinkedAccountsWithExpiringPassportsOrVisas(testExpirationCutoff));
    }
  }

  @Nested
  class GetExpiredLinkedAccountsWithPassports {
    @Test
    void testGetsOnlyExpiredLinkedAccounts() {
      // Create a not expired linked account with a passport
      var linkedAccount =
          TestUtils.createRandomPassportLinkedAccount()
              .withExpires(Timestamp.from(Instant.now().plus(Duration.ofMinutes(1))));
      var passport = TestUtils.createRandomPassport();

      var savedLinkedAccount = linkedAccountDAO.upsertLinkedAccount(linkedAccount);
      passportDAO.insertPassport(passport.withLinkedAccountId(savedLinkedAccount.getId()));

      // Create an expired linked account without a passport
      var linkedAccountWithoutPassport =
          TestUtils.createRandomLinkedAccount()
              .withExpires(Timestamp.from(Instant.now().minus(Duration.ofMinutes(1))));
      linkedAccountDAO.upsertLinkedAccount(linkedAccountWithoutPassport);

      // Create an expired linked account with a passport
      var expiredLinkedAccount =
          TestUtils.createRandomPassportLinkedAccount()
              .withExpires(Timestamp.from(Instant.now().minus(Duration.ofMinutes(1))));
      var expiredPassport = TestUtils.createRandomPassport();

      var savedExpiredLinkedAccount = linkedAccountDAO.upsertLinkedAccount(expiredLinkedAccount);
      passportDAO.insertPassport(
          expiredPassport.withLinkedAccountId(savedExpiredLinkedAccount.getId()));

      // Assert that only the expired linked account is returned
      assertEquals(
          List.of(savedExpiredLinkedAccount),
          linkedAccountDAO.getExpiredLinkedAccountsWithPassports());
    }
  }

  @Nested
  class GetLinkedAccountByPassportJwtId {
    @Test
    void testLinkedAccountExists() {
      var savedAccount =
          linkedAccountDAO.upsertLinkedAccount(TestUtils.createRandomLinkedAccount());
      var savedPassport =
          passportDAO.insertPassport(
              TestUtils.createRandomPassport().withLinkedAccountId(savedAccount.getId()));

      var loadedAccount =
          linkedAccountDAO.getLinkedAccountByPassportJwtIds(Set.of(savedPassport.getJwtId()));
      assertEquals(Map.of(savedPassport.getJwtId(), savedAccount), loadedAccount);
    }

    @Test
    void testMultipleLinkedAccountExists() {
      var savedAccount1 =
          linkedAccountDAO.upsertLinkedAccount(TestUtils.createRandomLinkedAccount());
      var savedPassport1 =
          passportDAO.insertPassport(
              TestUtils.createRandomPassport().withLinkedAccountId(savedAccount1.getId()));

      var savedAccount2 =
          linkedAccountDAO.upsertLinkedAccount(TestUtils.createRandomLinkedAccount());
      var savedPassport2 =
          passportDAO.insertPassport(
              TestUtils.createRandomPassport().withLinkedAccountId(savedAccount2.getId()));

      var loadedAccount =
          linkedAccountDAO.getLinkedAccountByPassportJwtIds(
              Set.of(savedPassport1.getJwtId(), savedPassport2.getJwtId()));
      assertEquals(
          Map.of(
              savedPassport1.getJwtId(), savedAccount1, savedPassport2.getJwtId(), savedAccount2),
          loadedAccount);
    }

    @Test
    void testLinkedAccountDoesNotExist() {
      linkedAccountDAO.upsertLinkedAccount(TestUtils.createRandomLinkedAccount());

      var loadedAccount =
          linkedAccountDAO.getLinkedAccountByPassportJwtIds(Set.of(UUID.randomUUID().toString()));
      assertTrue(loadedAccount.isEmpty());
    }
  }

  @Nested
  class LinkedAccountAdminFunctionality {

    @Test
    void testGetsLinkedAccountByExternalId() {
      var linkedAccount = TestUtils.createRandomLinkedAccount(Provider.ERA_COMMONS);
      linkedAccountDAO.upsertLinkedAccount(
          TestUtils.createRandomLinkedAccount(
              Provider.ERA_COMMONS)); // To make sure we get the right one.
      var savedLinkedAccount = linkedAccountDAO.upsertLinkedAccount(linkedAccount);
      var loadedLinkedAccount =
          linkedAccountDAO.getLinkedAccountForExternalId(
              Provider.ERA_COMMONS, savedLinkedAccount.getExternalUserId());

      // Assert that only the user_id for the username we supplied
      assertEquals(linkedAccount.getUserId(), loadedLinkedAccount.get().getUserId());
    }

    @Test
    void testGetsAllActiveLinkedAccounts() {
      // Create a non-expired linked account
      var linkedAccount = TestUtils.createRandomLinkedAccount(Provider.ERA_COMMONS);
      var linkedAccount2 = TestUtils.createRandomLinkedAccount(Provider.ERA_COMMONS);

      var savedLinkedAccount = linkedAccountDAO.upsertLinkedAccount(linkedAccount);
      var savedLinkedAccount2 = linkedAccountDAO.upsertLinkedAccount(linkedAccount2);

      // Create an expired linked account
      var expiredLinkedAccount =
          TestUtils.createRandomLinkedAccount(Provider.ERA_COMMONS)
              .withExpires(Timestamp.from(Instant.now().minus(Duration.ofMinutes(1))));
      linkedAccountDAO.upsertLinkedAccount(expiredLinkedAccount);

      // Create an unauthenticated linked account
      var unauthenticatedLinkedAccount =
          TestUtils.createRandomLinkedAccount(Provider.ERA_COMMONS).withIsAuthenticated(false);
      linkedAccountDAO.upsertLinkedAccount(unauthenticatedLinkedAccount);

      // Create a linked account with a different provider
      var linkedAccountDifferentProvider = TestUtils.createRandomLinkedAccount(Provider.GITHUB);
      linkedAccountDAO.upsertLinkedAccount(linkedAccountDifferentProvider);

      // Assert that only the non-expired, valid linked accounts
      // of the requested provider are returned
      assertEquals(
          List.of(savedLinkedAccount, savedLinkedAccount2),
          linkedAccountDAO.getActiveLinkedAccounts(Provider.ERA_COMMONS));
    }
  }
}

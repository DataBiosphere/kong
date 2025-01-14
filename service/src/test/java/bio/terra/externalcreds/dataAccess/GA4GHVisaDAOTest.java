package bio.terra.externalcreds.dataAccess;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import bio.terra.externalcreds.BaseTest;
import bio.terra.externalcreds.TestUtils;
import bio.terra.externalcreds.generated.model.Provider;
import bio.terra.externalcreds.models.TokenTypeEnum;
import bio.terra.externalcreds.models.VisaVerificationDetails;
import java.sql.Timestamp;
import java.time.Duration;
import java.time.Instant;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataAccessException;

class GA4GHVisaDAOTest extends BaseTest {

  @Autowired private LinkedAccountDAO linkedAccountDAO;
  @Autowired private GA4GHPassportDAO passportDAO;
  @Autowired private GA4GHVisaDAO visaDAO;

  @Nested
  class GetUnvalidatedAccessTokenVisaDetails {

    private final Timestamp validationCutoff =
        new Timestamp(Instant.now().minus(Duration.ofMinutes(60)).toEpochMilli());

    @Test
    void testGetUnvalidatedAccessTokenVisaDetails() {
      var recentlyValidatedTimestamp = new Timestamp(Instant.now().toEpochMilli());
      var expiredValidationTimestamp =
          new Timestamp(Instant.now().minus(Duration.ofDays(1)).toEpochMilli());

      // create linked account with passport and visa that does not need validation
      var savedLinkedAccount =
          linkedAccountDAO.upsertLinkedAccount(TestUtils.createRandomLinkedAccount());
      var savedPassport =
          passportDAO.insertPassport(
              TestUtils.createRandomPassport().withLinkedAccountId(savedLinkedAccount.getId()));
      var savedValidatedVisa =
          visaDAO.insertVisa(
              TestUtils.createRandomVisa()
                  .withLastValidated(recentlyValidatedTimestamp)
                  .withPassportId(savedPassport.getId()));

      // create linked account with passport and one visa that was NOT validated in the validation
      // window
      var savedLinkedAccountUnvalidatedVisa =
          linkedAccountDAO.upsertLinkedAccount(TestUtils.createRandomLinkedAccount());
      var savedPassportUnvalidatedVisa =
          passportDAO.insertPassport(
              TestUtils.createRandomPassport()
                  .withLinkedAccountId(savedLinkedAccountUnvalidatedVisa.getId()));
      var savedUnvalidatedVisa =
          visaDAO.insertVisa(
              TestUtils.createRandomVisa()
                  .withLastValidated(expiredValidationTimestamp)
                  .withPassportId(savedPassportUnvalidatedVisa.getId()));

      // create linked account with passport and one visa that was NOT validated in the validation
      // window and one that was to make sure it still returns the account info
      var savedLinkedAccountUnvalidatedVisa2 =
          linkedAccountDAO.upsertLinkedAccount(TestUtils.createRandomPassportLinkedAccount());
      var savedPassportUnvalidatedVisa2 =
          passportDAO.insertPassport(
              TestUtils.createRandomPassport()
                  .withLinkedAccountId(savedLinkedAccountUnvalidatedVisa2.getId()));
      var savedUnvalidatedVisa2 =
          visaDAO.insertVisa(
              TestUtils.createRandomVisa()
                  .withLastValidated(expiredValidationTimestamp)
                  .withPassportId(savedPassportUnvalidatedVisa2.getId()));
      var savedValidatedVisa2 =
          visaDAO.insertVisa(
              TestUtils.createRandomVisa()
                  .withLastValidated(recentlyValidatedTimestamp)
                  .withPassportId(savedPassportUnvalidatedVisa2.getId()));

      // create verified visa passport details to check unvalidated visa details against
      var passportWithUnvalidatedVisaDetails =
          new VisaVerificationDetails.Builder()
              .linkedAccountId(savedLinkedAccountUnvalidatedVisa.getId().get())
              .provider(savedLinkedAccountUnvalidatedVisa.getProvider())
              .visaJwt(savedUnvalidatedVisa.getJwt())
              .visaId(savedUnvalidatedVisa.getId().get())
              .build();

      var passportWithUnvalidatedVisaDetails2 =
          new VisaVerificationDetails.Builder()
              .linkedAccountId(savedLinkedAccountUnvalidatedVisa2.getId().get())
              .provider(savedLinkedAccountUnvalidatedVisa2.getProvider())
              .visaJwt(savedUnvalidatedVisa2.getJwt())
              .visaId(savedUnvalidatedVisa2.getId().get())
              .build();

      assertEquals(
          List.of(passportWithUnvalidatedVisaDetails, passportWithUnvalidatedVisaDetails2),
          visaDAO.getUnvalidatedAccessTokenVisaDetails(validationCutoff));
    }

    @Test
    void testGetsOnlyTokenTypeVisas() {
      // create linked account with passport and one token type visa NOT validated in the validation
      // window
      var savedLinkedAccountUnvalidatedVisa =
          linkedAccountDAO.upsertLinkedAccount(TestUtils.createRandomLinkedAccount());
      var savedPassportUnvalidatedVisa =
          passportDAO.insertPassport(
              TestUtils.createRandomPassport()
                  .withLinkedAccountId(savedLinkedAccountUnvalidatedVisa.getId()));
      var savedUnvalidatedVisa =
          visaDAO.insertVisa(
              TestUtils.createRandomVisa()
                  .withLastValidated(
                      new Timestamp(Instant.now().minus(Duration.ofDays(1)).toEpochMilli()))
                  .withPassportId(savedPassportUnvalidatedVisa.getId()));

      // create linked account with passport and one document type visa NOT validated in the
      // validation window
      var savedLinkedAccountUnvalidatedDocumentVisa =
          linkedAccountDAO.upsertLinkedAccount(TestUtils.createRandomLinkedAccount());
      var savedPassportUnvalidatedDocumentVisa =
          passportDAO.insertPassport(
              TestUtils.createRandomPassport()
                  .withLinkedAccountId(savedLinkedAccountUnvalidatedDocumentVisa.getId()));
      visaDAO.insertVisa(
          TestUtils.createRandomVisa()
              .withLastValidated(
                  new Timestamp(Instant.now().minus(Duration.ofDays(1)).toEpochMilli()))
              .withPassportId(savedPassportUnvalidatedDocumentVisa.getId())
              .withTokenType(TokenTypeEnum.document_token));

      // create verified visa passport details to check unvalidated visa details against
      var passportWithUnvalidatedVisaDetails =
          new VisaVerificationDetails.Builder()
              .linkedAccountId(savedLinkedAccountUnvalidatedVisa.getId().get())
              .provider(savedLinkedAccountUnvalidatedVisa.getProvider())
              .visaJwt(savedUnvalidatedVisa.getJwt())
              .visaId(savedUnvalidatedVisa.getId().get())
              .build();

      assertEquals(
          List.of(passportWithUnvalidatedVisaDetails),
          visaDAO.getUnvalidatedAccessTokenVisaDetails(validationCutoff));
    }
  }

  @Test
  void testInsertAndListVisa() {
    var savedLinkedAccount =
        linkedAccountDAO.upsertLinkedAccount(TestUtils.createRandomPassportLinkedAccount());
    var savedPassport =
        passportDAO.insertPassport(
            TestUtils.createRandomPassport().withLinkedAccountId(savedLinkedAccount.getId()));

    var baseVisa = TestUtils.createRandomVisa();
    var expectedVisa1 = baseVisa.withPassportId(savedPassport.getId());
    var expectedVisa2 =
        baseVisa.withPassportId(savedPassport.getId()).withTokenType(TokenTypeEnum.document_token);
    var savedVisa1 = visaDAO.insertVisa(expectedVisa1);
    var savedVisa2 = visaDAO.insertVisa(expectedVisa2);

    assertTrue(savedVisa1.getId().isPresent());
    assertTrue(savedVisa2.getId().isPresent());
    assertEquals(expectedVisa1, savedVisa1.withId(Optional.empty()));
    assertEquals(expectedVisa2, savedVisa2.withId(Optional.empty()));

    var loadedVisas =
        visaDAO.listVisas(savedLinkedAccount.getUserId(), savedLinkedAccount.getProvider());
    assertEquals(2, loadedVisas.size());
    assertEquals(Set.of(savedVisa1, savedVisa2), Set.copyOf(loadedVisas));
  }

  @Test
  void testInsertVisaWithInvalidForeignKey() {
    var invalidKeyVisa = TestUtils.createRandomVisa().withPassportId(-1);
    assertThrows(DataAccessException.class, () -> visaDAO.insertVisa(invalidKeyVisa));
  }

  @Test
  void testListNoVisas() {
    var loadedVisas = visaDAO.listVisas("foo", Provider.RAS);
    assertEquals(Collections.emptyList(), loadedVisas);
  }

  @Test
  void updateLastValidated() {
    var savedLinkedAccount =
        linkedAccountDAO.upsertLinkedAccount(TestUtils.createRandomLinkedAccount());
    var savedPassport =
        passportDAO.insertPassport(
            TestUtils.createRandomPassport().withLinkedAccountId(savedLinkedAccount.getId()));
    var savedVisa =
        visaDAO.insertVisa(TestUtils.createRandomVisa().withPassportId(savedPassport.getId()));

    Timestamp expectedLastValidated = new Timestamp(2363245);
    visaDAO.updateLastValidated(savedVisa.getId().get(), expectedLastValidated);

    var visas = visaDAO.listVisas(savedLinkedAccount.getUserId(), savedLinkedAccount.getProvider());
    assertEquals(1, visas.size());
    assertEquals(expectedLastValidated, visas.get(0).getLastValidated().get());
  }

  @Nested
  class ListUnexpiredVisasForIssuer {
    @Test
    void testHappyPath() {
      var randomVisa = TestUtils.createRandomVisa();

      // insert some other user with a visa to make sure it doesn't get returned
      var savedLinkedAccountOther =
          linkedAccountDAO.upsertLinkedAccount(TestUtils.createRandomLinkedAccount());
      var savedPassportOther =
          passportDAO.insertPassport(
              TestUtils.createRandomPassport()
                  .withLinkedAccountId(savedLinkedAccountOther.getId()));
      visaDAO.insertVisa(randomVisa.withPassportId(savedPassportOther.getId()));

      var savedLinkedAccount =
          linkedAccountDAO.upsertLinkedAccount(TestUtils.createRandomLinkedAccount());
      var savedPassport =
          passportDAO.insertPassport(
              TestUtils.createRandomPassport().withLinkedAccountId(savedLinkedAccount.getId()));
      var savedVisa = visaDAO.insertVisa(randomVisa.withPassportId(savedPassport.getId()));
      // insert some other visa to make sure it doesn't get returned
      visaDAO.insertVisa(TestUtils.createRandomVisa().withPassportId(savedPassport.getId()));

      var visas =
          visaDAO.listUnexpiredVisasForIssuer(
              savedLinkedAccount.getProvider(),
              savedLinkedAccount.getUserId(),
              savedVisa.getIssuer(),
              savedVisa.getVisaType());
      assertEquals(1, visas.size());
      assertEquals(savedVisa, visas.get(0));
    }

    @Test
    void testNoVisas() {
      var savedLinkedAccount =
          linkedAccountDAO.upsertLinkedAccount(TestUtils.createRandomLinkedAccount());
      var savedPassport =
          passportDAO.insertPassport(
              TestUtils.createRandomPassport().withLinkedAccountId(savedLinkedAccount.getId()));
      var savedVisa =
          visaDAO.insertVisa(TestUtils.createRandomVisa().withPassportId(savedPassport.getId()));
      assertEquals(
          0,
          visaDAO
              .listUnexpiredVisasForIssuer(
                  savedLinkedAccount.getProvider(),
                  savedLinkedAccount.getUserId(),
                  "different_issuer",
                  savedVisa.getVisaType())
              .size());
      assertEquals(
          0,
          visaDAO
              .listUnexpiredVisasForIssuer(
                  savedLinkedAccount.getProvider(),
                  savedLinkedAccount.getUserId(),
                  savedVisa.getIssuer(),
                  "different_type")
              .size());
    }

    @Test
    void testExpiredVisas() {
      var savedLinkedAccount =
          linkedAccountDAO.upsertLinkedAccount(TestUtils.createRandomLinkedAccount());
      var savedPassport =
          passportDAO.insertPassport(
              TestUtils.createRandomPassport().withLinkedAccountId(savedLinkedAccount.getId()));
      var savedVisa =
          visaDAO.insertVisa(
              TestUtils.createRandomVisa()
                  .withPassportId(savedPassport.getId())
                  .withExpires(
                      new Timestamp(Instant.now().minus(Duration.ofDays(1)).toEpochMilli())));
      var visas =
          visaDAO.listUnexpiredVisasForIssuer(
              savedLinkedAccount.getProvider(),
              savedLinkedAccount.getUserId(),
              savedVisa.getIssuer(),
              savedVisa.getVisaType());
      assertEquals(0, visas.size());
    }
  }
}

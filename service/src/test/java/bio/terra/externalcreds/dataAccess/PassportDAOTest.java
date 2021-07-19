package bio.terra.externalcreds.dataAccess;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import bio.terra.externalcreds.BaseTest;
import bio.terra.externalcreds.models.GA4GHPassport;
import bio.terra.externalcreds.models.GA4GHVisa;
import bio.terra.externalcreds.models.LinkedAccount;
import bio.terra.externalcreds.models.TokenTypeEnum;
import java.sql.Timestamp;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.test.annotation.Rollback;
import org.springframework.transaction.annotation.Transactional;

public class PassportDAOTest extends BaseTest {

  @Autowired private LinkedAccountDAO linkedAccountDAO;
  @Autowired private GA4GHPassportDAO passportDAO;
  @Autowired private GA4GHVisaDAO visaDAO;

  private GA4GHPassport passport;
  private LinkedAccount linkedAccount;

  @BeforeEach
  void setup() {
    linkedAccount =
        LinkedAccount.builder()
            .expires(new Timestamp(100))
            .providerId("provider")
            .refreshToken("refresh")
            .userId(UUID.randomUUID().toString())
            .externalUserId("externalUser")
            .build();

    passport = GA4GHPassport.builder().jwt("fake-jwt").expires(new Timestamp(100)).build();
  }

  @Test
  void testMissingPassport() {
    var shouldBeNull = passportDAO.getPassport(-1);
    assertNull(shouldBeNull);
  }

  @Test
  @Transactional
  @Rollback
  void testCreateAndGetPassport() {
    var savedAccount = linkedAccountDAO.upsertLinkedAccount(linkedAccount);
    var savedPassport =
        passportDAO.insertPassport(passport.withLinkedAccountId(savedAccount.getId()));
    assertTrue(savedPassport.getId() > 0);
    assertEquals(
        passport
            .withId(savedPassport.getId())
            .withLinkedAccountId(savedPassport.getLinkedAccountId()),
        savedPassport);

    var loadedPassport = passportDAO.getPassport(savedAccount.getId());
    assertEquals(savedPassport, loadedPassport);
  }

  @Test
  @Transactional
  @Rollback
  void testPassportIsUniqueForLinkedAccount() {
    var savedAccount = linkedAccountDAO.upsertLinkedAccount(linkedAccount);
    var savedPassport =
        passportDAO.insertPassport(passport.withLinkedAccountId(savedAccount.getId()));

    assertThrows(
        DuplicateKeyException.class,
        () ->
            passportDAO.insertPassport(
                savedPassport.withExpires(new Timestamp(200)).withJwt("different-jwt")));
  }

  @Nested
  class DeletePassport {

    @Test
    @Transactional
    @Rollback
    void testDeletePassportIfExists() {
      var savedAccount = linkedAccountDAO.upsertLinkedAccount(linkedAccount);
      passportDAO.insertPassport(passport.withLinkedAccountId(savedAccount.getId()));

      assertNotNull(passportDAO.getPassport(savedAccount.getId()));
      assertTrue(passportDAO.deletePassport(savedAccount.getId()));
      assertNull(passportDAO.getPassport(savedAccount.getId()));
    }

    @Test
    @Transactional
    @Rollback
    void testDeleteNonexistentPassport() {
      assertFalse(passportDAO.deletePassport(-1));
    }

    @Test
    @Transactional
    @Rollback
    void testAlsoDeletesVisa() {
      var savedAccount = linkedAccountDAO.upsertLinkedAccount(linkedAccount);
      var savedPassport =
          passportDAO.insertPassport(passport.withLinkedAccountId(savedAccount.getId()));

      visaDAO.insertVisa(
          GA4GHVisa.builder()
              .visaType("fake")
              .passportId(savedPassport.getId())
              .tokenType(TokenTypeEnum.access_token)
              .expires(new Timestamp(150))
              .issuer("fake-issuer")
              .lastValidated(new Timestamp(125))
              .jwt("fake-jwt")
              .build());

      assertFalse(visaDAO.listVisas(savedPassport.getId()).isEmpty());
      assertTrue(passportDAO.deletePassport(savedAccount.getId()));
      assertTrue(visaDAO.listVisas(savedPassport.getId()).isEmpty());
    }
  }
}

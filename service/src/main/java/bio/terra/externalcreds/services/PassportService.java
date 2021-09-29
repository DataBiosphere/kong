package bio.terra.externalcreds.services;

import bio.terra.common.db.ReadTransaction;
import bio.terra.externalcreds.config.ExternalCredsConfig;
import bio.terra.externalcreds.dataAccess.GA4GHPassportDAO;
import bio.terra.externalcreds.dataAccess.GA4GHVisaDAO;
import bio.terra.externalcreds.models.GA4GHPassport;
import bio.terra.externalcreds.models.VisaVerificationDetails;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

@Service
@Slf4j
public class PassportService {

  private final GA4GHPassportDAO passportDAO;
  private final ExternalCredsConfig externalCredsConfig;
  private final GA4GHVisaDAO visaDAO;

  public PassportService(
      GA4GHPassportDAO passportDAO, ExternalCredsConfig externalCredsConfig, GA4GHVisaDAO visaDAO) {
    this.passportDAO = passportDAO;
    this.externalCredsConfig = externalCredsConfig;
    this.visaDAO = visaDAO;
  }

  @ReadTransaction
  public Optional<GA4GHPassport> getPassport(String userId, String providerId) {
    return passportDAO.getPassport(userId, providerId);
  }

  @ReadTransaction
  public List<VisaVerificationDetails> getUnvalidatedAccessTokenVisaDetails() {
    var validationCutoff =
        new Timestamp(
            Instant.now().minus(externalCredsConfig.getTokenValidationDuration()).toEpochMilli());
    return visaDAO.getUnvalidatedAccessTokenVisaDetails(validationCutoff);
  }
}

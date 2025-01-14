package bio.terra.externalcreds.services;

import bio.terra.common.db.ReadTransaction;
import bio.terra.common.db.WriteTransaction;
import bio.terra.common.exception.BadRequestException;
import bio.terra.externalcreds.ExternalCredsException;
import bio.terra.externalcreds.config.ExternalCredsConfig;
import bio.terra.externalcreds.dataAccess.GA4GHPassportDAO;
import bio.terra.externalcreds.dataAccess.GA4GHVisaDAO;
import bio.terra.externalcreds.dataAccess.LinkedAccountDAO;
import bio.terra.externalcreds.generated.model.Provider;
import bio.terra.externalcreds.models.GA4GHPassport;
import bio.terra.externalcreds.models.GA4GHVisa;
import bio.terra.externalcreds.models.LinkedAccount;
import bio.terra.externalcreds.models.PassportWithVisas;
import bio.terra.externalcreds.models.ValidatePassportResultInternal;
import bio.terra.externalcreds.models.VisaVerificationDetails;
import bio.terra.externalcreds.visaComparators.VisaComparator;
import bio.terra.externalcreds.visaComparators.VisaCriterionInternal;
import java.sql.Timestamp;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Service;

@Service
@Slf4j
public class PassportService {

  private final LinkedAccountDAO linkedAccountDAO;
  private final GA4GHPassportDAO passportDAO;
  private final ExternalCredsConfig externalCredsConfig;
  private final GA4GHVisaDAO visaDAO;
  private final JwtUtils jwtUtils;
  private final Collection<VisaComparator> visaComparators;

  private static final Duration VISA_VALIDITY_TIME = Duration.of(1, ChronoUnit.HOURS);

  public PassportService(
      LinkedAccountDAO linkedAccountDAO,
      GA4GHPassportDAO passportDAO,
      ExternalCredsConfig externalCredsConfig,
      GA4GHVisaDAO visaDAO,
      Collection<VisaComparator> visaComparators,
      JwtUtils jwtUtils) {
    this.linkedAccountDAO = linkedAccountDAO;
    this.passportDAO = passportDAO;
    this.externalCredsConfig = externalCredsConfig;
    this.visaDAO = visaDAO;
    this.jwtUtils = jwtUtils;
    this.visaComparators = visaComparators;
  }

  @ReadTransaction
  public Optional<GA4GHPassport> getPassport(String userId, Provider provider) {
    return passportDAO.getPassport(userId, provider);
  }

  @ReadTransaction
  public List<VisaVerificationDetails> getUnvalidatedAccessTokenVisaDetails() {
    var validationCutoff =
        new Timestamp(
            Instant.now().minus(externalCredsConfig.getTokenValidationDuration()).toEpochMilli());
    return visaDAO.getUnvalidatedAccessTokenVisaDetails(validationCutoff);
  }

  @WriteTransaction
  public void updateVisaLastValidated(int visaId) {
    visaDAO.updateLastValidated(visaId, new Timestamp(Instant.now().toEpochMilli()));
  }

  /**
   * @param passportJwtStrings
   * @param criteria
   * @return
   */
  @ReadTransaction
  public ValidatePassportResultInternal validatePassport(
      Collection<String> passportJwtStrings, Collection<VisaCriterionInternal> criteria) {

    var passports = decodeAndValidatePassports(passportJwtStrings);
    var linkedAccountsByJwtId = getLinkedAccountsForAllPassports(passports);

    for (var passportWithVisas : passports) {
      var transactionClaim =
          jwtUtils.getJwtTransactionClaim(passportWithVisas.getPassport().getJwt());
      for (var criterion : criteria) {
        for (var visa : passportWithVisas.getVisas()) {
          VisaComparator visaComparator = getVisaComparator(criterion);
          if (visaComparator.visaTypeSupported(visa)
              && visa.getIssuer().equals(criterion.getIssuer())
              && visaComparator.matchesCriterion(visa, criterion)) {
            var auditInfoMap =
                new HashMap<>(Map.of("passport_jti", passportWithVisas.getPassport().getJwtId()));
            transactionClaim.map(t -> auditInfoMap.put("txn", t));
            var jwtId = passportWithVisas.getPassport().getJwtId();
            var linkedAccount =
                Optional.ofNullable(
                    linkedAccountsByJwtId.get(passportWithVisas.getPassport().getJwtId()));
            var passportValid =
                linkedAccount
                    .map(
                        l -> {
                          log.info("Found internal user {} for passport {}", l.getUserId(), jwtId);
                          auditInfoMap.putAll(
                              Map.of(
                                  "external_user_id", l.getExternalUserId(),
                                  "internal_user_id", l.getUserId()));
                          return true;
                        })
                    .orElseGet(
                        () -> {
                          log.info(
                              "No internal user found for passport {}. Checking issue time...",
                              passportWithVisas.getPassport().getJwtId());
                          return isPassportIssueTimeValid(passportWithVisas.getPassport());
                        });
            if (passportValid) {
              return new ValidatePassportResultInternal.Builder()
                  .valid(true)
                  .matchedCriterion(criterion)
                  .auditInfo(auditInfoMap)
                  .build();
            }
          }
        }
      }
    }

    // if we got this far there was no matching visa
    var invalidResult = new ValidatePassportResultInternal.Builder().valid(false);
    if (!linkedAccountsByJwtId.isEmpty()) {
      var linkedAccount = linkedAccountsByJwtId.values().iterator().next();
      invalidResult.auditInfo(Map.of("internal_user_id", linkedAccount.getUserId()));
    }
    return invalidResult.build();
  }

  @ReadTransaction
  public List<Map<String, Object>> getVisaClaims(
      Provider provider, String userId, String issuer, String visaType) {
    return visaDAO.listUnexpiredVisas(provider, userId, issuer, visaType).stream()
        .map(GA4GHVisa::getJwt)
        .map(jwtUtils::decodeAndValidateJwt)
        .map(Jwt::getClaims)
        .toList();
  }

  private boolean isPassportIssueTimeValid(GA4GHPassport passport) {
    int comparison =
        Duration.between(jwtUtils.getJwtIssuedAt(passport.getJwt()).toInstant(), Instant.now())
            .compareTo(VISA_VALIDITY_TIME);
    return comparison < 0;
  }

  private Collection<PassportWithVisas> decodeAndValidatePassports(
      Collection<String> passportJwtStrings) {
    try {
      return passportJwtStrings.stream().map(jwtUtils::decodeAndValidatePassportJwtString).toList();
    } catch (InvalidJwtException e) {
      throw new BadRequestException("invalid passport jwt", e);
    }
  }

  private Map<String, LinkedAccount> getLinkedAccountsForAllPassports(
      Collection<PassportWithVisas> passportWithVisas) {
    var linkedAccounts =
        linkedAccountDAO.getLinkedAccountByPassportJwtIds(
            passportWithVisas.stream()
                .map(p -> p.getPassport().getJwtId())
                .collect(Collectors.toSet()));

    if (linkedAccounts.values().stream()
            .map(LinkedAccount::getUserId)
            .collect(Collectors.toSet())
            .size()
        > 1) {
      throw new BadRequestException(
          "a single request to validate passports can contain only passports from the same user");
    }
    return linkedAccounts;
  }

  private VisaComparator getVisaComparator(VisaCriterionInternal criterion) {
    return visaComparators.stream()
        .filter(c -> c.criterionTypeSupported(criterion))
        .findFirst()
        .orElseThrow(
            () ->
                new ExternalCredsException(
                    String.format("comparator not found for visa criterion %s", criterion)));
  }
}

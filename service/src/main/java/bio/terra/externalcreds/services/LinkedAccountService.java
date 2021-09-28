package bio.terra.externalcreds.services;

import bio.terra.common.db.ReadTransaction;
import bio.terra.common.db.WriteTransaction;
import bio.terra.externalcreds.dataAccess.GA4GHPassportDAO;
import bio.terra.externalcreds.dataAccess.GA4GHVisaDAO;
import bio.terra.externalcreds.dataAccess.LinkedAccountDAO;
import bio.terra.externalcreds.models.AuthorizationChangeEvent;
import bio.terra.externalcreds.models.GA4GHVisa;
import bio.terra.externalcreds.models.LinkedAccount;
import bio.terra.externalcreds.models.LinkedAccountWithPassportAndVisas;
import bio.terra.externalcreds.visaComparators.VisaComparator;
import java.sql.Timestamp;
import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

@Service
@Slf4j
public class LinkedAccountService {

  private final LinkedAccountDAO linkedAccountDAO;
  private final GA4GHPassportDAO ga4ghPassportDAO;
  private final GA4GHVisaDAO ga4ghVisaDAO;
  private final Collection<VisaComparator> visaComparators;
  private final EventPublisher eventPublisher;

  public LinkedAccountService(
      LinkedAccountDAO linkedAccountDAO,
      GA4GHPassportDAO ga4ghPassportDAO,
      GA4GHVisaDAO ga4ghVisaDAO,
      Collection<VisaComparator> visaComparators,
      EventPublisher eventPublisher) {
    this.linkedAccountDAO = linkedAccountDAO;
    this.ga4ghPassportDAO = ga4ghPassportDAO;
    this.ga4ghVisaDAO = ga4ghVisaDAO;
    this.visaComparators = visaComparators;
    this.eventPublisher = eventPublisher;
  }

  @ReadTransaction
  public Optional<LinkedAccount> getLinkedAccount(int linkedAccountId) {
    return linkedAccountDAO.getLinkedAccount(linkedAccountId);
  }

  @ReadTransaction
  public Optional<LinkedAccount> getLinkedAccount(String userId, String providerId) {
    return linkedAccountDAO.getLinkedAccount(userId, providerId);
  }

  @WriteTransaction
  public LinkedAccountWithPassportAndVisas upsertLinkedAccountWithPassportAndVisas(
      LinkedAccountWithPassportAndVisas linkedAccountWithPassportAndVisas) {
    var linkedAccount = linkedAccountWithPassportAndVisas.getLinkedAccount();
    var existingVisas =
        ga4ghVisaDAO.listVisas(linkedAccount.getUserId(), linkedAccount.getProviderId());
    var savedLinkedAccount = linkedAccountDAO.upsertLinkedAccount(linkedAccount);

    // clear out any passport and visas that may exist and save the new one
    ga4ghPassportDAO.deletePassport(savedLinkedAccount.getId().orElseThrow());

    var savedLinkedAccountWithPassportAndVisas =
        savePassportAndVisasIfPresent(
            linkedAccountWithPassportAndVisas.withLinkedAccount(savedLinkedAccount));

    if (authorizationsDiffer(existingVisas, savedLinkedAccountWithPassportAndVisas.getVisas())) {
      eventPublisher.publishAuthorizationChangeEvent(
          new AuthorizationChangeEvent.Builder()
              .providerId(savedLinkedAccount.getProviderId())
              .userId(savedLinkedAccount.getUserId())
              .build());
    }

    return savedLinkedAccountWithPassportAndVisas;
  }

  @WriteTransaction
  public LinkedAccount upsertLinkedAccount(LinkedAccount linkedAccount) {
    return linkedAccountDAO.upsertLinkedAccount(linkedAccount);
  }

  @WriteTransaction
  public boolean deleteLinkedAccount(String userId, String providerId) {
    var existingVisas = ga4ghVisaDAO.listVisas(userId, providerId);
    var accountExisted = linkedAccountDAO.deleteLinkedAccountIfExists(userId, providerId);
    if (!existingVisas.isEmpty()) {
      eventPublisher.publishAuthorizationChangeEvent(
          new AuthorizationChangeEvent.Builder().providerId(providerId).userId(userId).build());
    }
    return accountExisted;
  }

  @ReadTransaction
  public List<LinkedAccount> getExpiringLinkedAccounts(Timestamp expirationCutoff) {
    return linkedAccountDAO.getExpiringLinkedAccounts(expirationCutoff);
  }

  private LinkedAccountWithPassportAndVisas savePassportAndVisasIfPresent(
      LinkedAccountWithPassportAndVisas linkedAccountWithPassportAndVisas) {
    if (linkedAccountWithPassportAndVisas.getPassport().isPresent()) {

      var savedPassport =
          ga4ghPassportDAO.insertPassport(
              linkedAccountWithPassportAndVisas
                  .getPassport()
                  .get()
                  .withLinkedAccountId(
                      linkedAccountWithPassportAndVisas.getLinkedAccount().getId()));

      var savedVisas =
          linkedAccountWithPassportAndVisas.getVisas().stream()
              .map(v -> ga4ghVisaDAO.insertVisa(v.withPassportId(savedPassport.getId())))
              .collect(Collectors.toList());

      return linkedAccountWithPassportAndVisas.withPassport(savedPassport).withVisas(savedVisas);
    } else {
      return linkedAccountWithPassportAndVisas;
    }
  }

  private boolean authorizationsDiffer(
      Collection<GA4GHVisa> existingVisas, Collection<GA4GHVisa> newVisas) {
    if (existingVisas.size() != newVisas.size()) {
      // number of visas differ so there isn't a way to compare, assume authorizations differ
      return true;
    }

    // We want to make sure there is a 1 to 1 match between newVisas and existingVisas
    // order does not matter and there is no way to sort such that we can compare pairwise.
    // Match all newVisas to an existingVisa
    var matchingVisas =
        newVisas.stream().flatMap(newVisa -> findMatchingVisa(newVisa, existingVisas).stream());
    // If the count of distinct matchingVisas is not the same as the count of distinct
    // existingVisas, either at least 1 newVisa did not find a match or at least 1 existingVisa was
    // matched more than once, thus authorizations differ.
    return matchingVisas.distinct().count() != existingVisas.stream().distinct().count();
  }

  private Optional<GA4GHVisa> findMatchingVisa(
      GA4GHVisa newVisa, Collection<GA4GHVisa> visasToCheck) {
    return getVisaComparator(newVisa)
        .map(
            visaComparator ->
                visasToCheck.stream()
                    .filter(
                        existingVisa -> visaComparator.authorizationsMatch(newVisa, existingVisa))
                    .findFirst())
        .orElseGet(
            () -> {
              log.error("could not find visa comparator for visa type {}", newVisa.getVisaType());
              return Optional.empty();
            });
  }

  private Optional<VisaComparator> getVisaComparator(GA4GHVisa visa) {
    return visaComparators.stream().filter(c -> c.visaTypeSupported(visa)).findFirst();
  }
}

ENV=${1:-dev}
VAULT_TOKEN=${2:-$(cat "$HOME"/.vault-token)}
LIVE_DB=${3:-false}

VAULT_ADDR="https://clotho.broadinstitute.org:8200"
if [ $ENV == 'prod' ]; then
  ECM_VAULT_PATH="secret/suitable/terra/kernel/prod/prod/externalcreds"
else
  ECM_VAULT_PATH="secret/dsde/terra/kernel/$ENV/$ENV/externalcreds"
fi
COMMON_VAULT_PATH="secret/dsde/terra/kernel/$ENV/common"

VAULT_COMMAND="vault read"

SERVICE_OUTPUT_LOCATION="$(dirname "$0")/service/src/main/resources/rendered"
SECRET_ENV_VARS_LOCATION="${SERVICE_OUTPUT_LOCATION}/secrets.env"
INTEGRATION_OUTPUT_LOCATION="$(dirname "$0")/integration/src/main/resources/rendered"

if ! [ -x "$(command -v vault)" ]; then
  VAULT_COMMAND="docker run --rm -e VAULT_TOKEN=$VAULT_TOKEN -e VAULT_ADDR=$VAULT_ADDR vault:1.7.3 $VAULT_COMMAND"
fi


if [ -f "${SECRET_ENV_VARS_LOCATION}" ]; then
  rm "${SECRET_ENV_VARS_LOCATION}"
fi


GOOGLE_PROJECT=broad-dsde-${ENV}
{
  if $LIVE_DB; then
    echo export DATABASE_NAME="$(gcloud secrets versions access latest --secret=externalcreds-postgres-creds --project="${GOOGLE_PROJECT}" | jq -r '.db')"
    echo export DATABASE_USER="$(gcloud secrets versions access latest --secret=externalcreds-postgres-creds --project="${GOOGLE_PROJECT}" | jq -r '.username')"
    echo export DATABASE_USER_PASSWORD="$(gcloud secrets versions access latest --secret=externalcreds-postgres-creds --project="${GOOGLE_PROJECT}" | jq -r '.password')"
  fi

  if [ $ENV != 'prod' ]; then
      echo export RAS_CLIENT_ID="$(gcloud secrets versions access latest --secret=externalcreds-providers --project="${GOOGLE_PROJECT}" | jq -r '.ras_client_id')"
      echo export RAS_CLIENT_SECRET="$(gcloud secrets versions access latest --secret=externalcreds-providers --project="${GOOGLE_PROJECT}" | jq -r '.ras_client_secret')"
      echo export ERA_COMMONS_CLIENT_ID="$(gcloud secrets versions access latest --secret=externalcreds-providers --project="${GOOGLE_PROJECT}" | jq -r '.era_commons_client_id')"
      echo export ERA_COMMONS_CLIENT_SECRET="$(gcloud secrets versions access latest --secret=externalcreds-providers --project="${GOOGLE_PROJECT}" | jq -r '.era_commons_client_secret')"
  fi

  echo export GITHUB_CLIENT_ID="$(gcloud secrets versions access latest --secret=externalcreds-providers --project="${GOOGLE_PROJECT}" | jq -r '.github_client_id')"
  echo export GITHUB_CLIENT_SECRET="$(gcloud secrets versions access latest --secret=externalcreds-providers --project="${GOOGLE_PROJECT}" | jq -r '.github_client_secret')"
  echo export ANVIL_CLIENT_ID="$(gcloud secrets versions access latest --secret=externalcreds-fence --project="${GOOGLE_PROJECT}" | jq -r '."anvil-client-id"')"
  echo export ANVIL_CLIENT_SECRET="$(gcloud secrets versions access latest --secret=externalcreds-fence --project="${GOOGLE_PROJECT}" | jq -r '."anvil-client-secret"')"
  echo export FENCE_CLIENT_ID="$(gcloud secrets versions access latest --secret=externalcreds-fence --project="${GOOGLE_PROJECT}" | jq -r '."client-id"')"
  echo export FENCE_CLIENT_SECRET="$(gcloud secrets versions access latest --secret=externalcreds-fence --project="${GOOGLE_PROJECT}" | jq -r '."client-secret"')"
  echo export DCF_FENCE_CLIENT_ID="$(gcloud secrets versions access latest --secret=externalcreds-fence --project="${GOOGLE_PROJECT}" | jq -r '."dcf-fence-client-id"')"
  echo export DCF_FENCE_CLIENT_SECRET="$(gcloud secrets versions access latest --secret=externalcreds-fence --project="${GOOGLE_PROJECT}" | jq -r '."dcf-fence-client-secret"')"
  echo export KIDS_FIRST_CLIENT_ID="$(gcloud secrets versions access latest --secret=externalcreds-fence --project="${GOOGLE_PROJECT}" | jq -r '."kids-first-client-id"')"
  echo export KIDS_FIRST_CLIENT_SECRET="$(gcloud secrets versions access latest --secret=externalcreds-fence --project="${GOOGLE_PROJECT}" | jq -r '."kids-first-client-secret"')"

  echo export DEPLOY_ENV=$ENV
  echo export SAM_ADDRESS=https://sam.dsde-${ENV}.broadinstitute.org
} >> "${SECRET_ENV_VARS_LOCATION}"

gcloud secrets versions access latest --secret=externalcreds-swagger-client-id --project="${GOOGLE_PROJECT}" | jq -r '."swagger-client-id"' >"$SERVICE_OUTPUT_LOCATION/swagger-client-id"

$VAULT_COMMAND -field=data -format=json "secret/dsde/firecloud/$ENV/common/firecloud-account.json" >"$INTEGRATION_OUTPUT_LOCATION/user-delegated-sa.json"

if [ $ENV == perf ]; then
  $VAULT_COMMAND -field=key "$COMMON_VAULT_PATH/testrunner/testrunner-sa" | base64 -d > "$INTEGRATION_OUTPUT_LOCATION/testrunner-sa.json"
  else
    $VAULT_COMMAND -field=key "$ECM_VAULT_PATH/app-sa" | base64 -d > "$SERVICE_OUTPUT_LOCATION/ecm-sa.json"
fi

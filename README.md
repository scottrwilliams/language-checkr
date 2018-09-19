# language-checkr
Creates a serverless endpoint for a GitHub App to check if translations are valid.

## Creating a GitHub App

1. Clone this repository
2. `npm install`
3. Generate a secret token (i.e. `ruby -rsecurerandom -e 'puts SecureRandom.hex(20)'`)
4. Register a [new GitHub app](https://developer.github.com/apps/building-integrations/setting-up-and-registering-github-apps/registering-github-apps/). Use token from step 3 for the "Webhook secret"
5. Required App permissions & webhooks:
* Set `Checks` permission to `Read & write`
* Set `Repository contents` permission to `Read-only`
* Set `Pull requests` permission to `Read-only`
* Every other permission should be set to `No access`
* No webhooks need to be selected under `Subscribe to events`. GitHub will automatically send `check_suite` and `check_run` events
6. Save app and make note of the App Id
7. [Generate a private key](https://developer.github.com/apps/building-integrations/setting-up-and-registering-github-apps/registering-github-apps/#generating-a-private-key) for the App and save it
8. Ensure serverless is [configured with appropriate AWS credentials](https://serverless.com/framework/docs/providers/aws/guide/quick-start/)
9. Run a severless deploy `npm run deploy -- --app_id [from step 6] --webhook_secret [from step 3]`. Note the endpoint URL that comes back
10. Go back into the GitHub App settings and set the "Webhook URL" to the endpoint URL from step 9
11. Take the private key from step 7 and store it as `key.pem` in an S3 bucket called `languagecheckr-cfg` (or override environment variables `PEM_BUCKET_NAME` and `PEM_KEY`)
12. [Install](https://developer.github.com/apps/building-integrations/setting-up-and-registering-github-apps/about-installation-options-for-github-apps/) and enable the App for your GitHub organization and/or selected repos

## Using language-checkr

Uses [GitHub Checks API](https://developer.github.com/v3/checks/) to show any problems with translations.

#### Skip checks

Use `skip-checks: true`, as described [here](https://help.github.com/articles/about-status-checks/#skipping-and-requesting-checks-for-individual-commits)

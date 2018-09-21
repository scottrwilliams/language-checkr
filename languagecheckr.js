'use strict';

const GitHubApi = require('@octokit/rest'),
  AWS = require('aws-sdk'),
  jwt = require('jsonwebtoken'),
  crypto = require('crypto'),
  path = require('path'),
  langValidator = require('messageformat-validator');

function validateSignature(body, xHubSignature) {
  const hmac = crypto.createHmac('sha1', process.env.WEBHOOK_SECRET);
  const bodySig = `sha1=${hmac.update(body).digest('hex')}`;
  const bufferBodySig = Buffer.from(bodySig, 'utf8');
  const bufferXHubSig = Buffer.from(xHubSignature, 'utf8');
  return crypto.timingSafeEqual(bufferBodySig, bufferXHubSig);
}

const privateKey = (async () => {
  const file = await new AWS.S3().getObject({
    Bucket: process.env.PEM_BUCKET_NAME,
    Key: process.env.PEM_KEY
  }).promise();
  return file.Body.toString('utf8');
})();

async function gitHubAuthenticate(appId, cert, installationId) {
  const github = new GitHubApi();
  const payload = {
    iat: Math.floor(new Date() / 1000),
    exp: Math.floor(new Date() / 1000) + 30,
    iss: appId
  };

  github.authenticate({
    type: 'app',
    token: jwt.sign(payload, cert, {
      algorithm: 'RS256'
    })
  });

  const installationToken = await github.apps.createInstallationToken({
    installation_id: installationId
  });

  github.authenticate({
    type: 'token',
    token: installationToken.data.token
  });
  return github;
}

async function getLanguageFiles(github, owner, repo, headSha, pullRequestNumber) {

  const allFiles = await github.pullRequests.getFiles({
    owner,
    repo,
    number: pullRequestNumber
  });

  const languageFiles = allFiles.data.filter(file =>
    file.status !== 'removed' &&
    file.filename.startsWith('locale/') &&
    file.filename.endsWith('.json')
  );

  return Promise.all(languageFiles.map(async file => {
    const fileContents = await github.repos.getContent({
      owner,
      repo,
      ref: headSha,
      path: file.filename
    });
    return {
      filePath: file.filename,
      fileName: path.basename(file.filename, '.json'),
      fileText: Buffer.from(fileContents.data.content, 'base64').toString()
    };
  }));
}

async function updateCheck(github, owner, repo, sha, languageFiles) {

  if (languageFiles.length == 0) {
    return github.checks.create({
      owner,
      repo,
      name: 'Language Checker',
      head_sha: sha,
      status: 'completed',
      conclusion: 'neutral',
      completed_at: new Date().toISOString(),
      output: {
        title: 'Language files',
        summary: 'Did not find any translations'
      }
    });
  }

  const fileLookup = new Map();
  languageFiles.forEach(file => {
    fileLookup.set(file.fileName, file.filePath);
  });

  const locales = languageFiles.reduce(
    (obj, file) => {
      obj[file.fileName] = file.fileText;
      return obj;
    }, {}
  );

  console.log(JSON.stringify({
    locales,
    sourceLocale: 'en'
  }));

  const output = langValidator.validateLocales({
    locales,
    sourceLocale: 'en'
  });

  console.log(JSON.stringify(output));

  //TODO: always ensure english file sent
  //TODO: handle English failure

  return Promise.all(output.map(locale => {

    //TODO: markdown output

    if (!locale.parsed) {
      return github.checks.create({
        owner,
        repo,
        name: `File: ${locale.locale}.json`,
        head_sha: sha,
        status: 'completed',
        conclusion: 'failure',
        completed_at: new Date().toISOString(),
        output: {
          title: 'The translation file is not valid',
          summary: JSON.stringify(locale._error) //TODO: add extra msg if locale is source locale
        }
      });
    }

    const errors = locale.report.totals.errors;
    const warnings = locale.report.totals.warnings;

    if (errors === 0 && warnings == 0) {
      return github.checks.create({
        owner,
        repo,
        name: `File: ${locale.locale}.json`,
        head_sha: sha,
        status: 'completed',
        conclusion: 'success',
        completed_at: new Date().toISOString(),
        output: {
          title: 'No issues with translations',
          summary: 'Yay!'
        }
      });
    }

    //cap annotations at 50
    //TODO: also display a message if issues were capped
    locale.issues.length = Math.min(locale.issues.length, 50);

    return github.checks.create({
      owner,
      repo,
      name: `File: ${locale.locale}.json`,
      head_sha: sha,
      status: 'completed',
      conclusion: errors === 0 ? 'neutral' : 'failure',
      completed_at: new Date().toISOString(),
      output: {
        title: `Found ${errors} error(s), ${warnings} warning(s)`,
        summary: JSON.stringify(locale),
        annotations: locale.issues.map(issue => ({
          path: fileLookup.get(locale.locale),
          start_line: issue.line, //TODO: column?
          end_line: issue.line,
          annotation_level: issue.level,
          title: `${issue.type} ${issue.level}`,
          message: `"${issue.key}": ${issue.msg}`
        }))
      }
    });
  }));
}

function createResponse(statusCode, msg) {
  return {
    statusCode: statusCode,
    headers: {
      'Content-Type': 'text/plain'
    },
    body: msg
  };
}

module.exports.handler = async (event, context, callback) => {

  const githubEvent = event.headers['X-GitHub-Event'];
  if (!githubEvent) {
    return callback(null, createResponse(400, 'Missing X-GitHub-Event'));
  }

  const sig = event.headers['X-Hub-Signature'];
  if (!sig) {
    return callback(null, createResponse(400, 'Missing X-Hub-Signature'));
  }
  if (!validateSignature(event.body, sig)) {
    return callback(null, createResponse(400, 'Invalid X-Hub-Signature'));
  }

  const webHook = JSON.parse(event.body);
  let pullRequestNumber, headSha;
  if (githubEvent === 'check_suite' &&
    (webHook.action === 'requested' || webHook.action === 'rerequested')) {
    pullRequestNumber = webHook.check_suite.pull_requests[0].number;
    headSha = webHook.check_suite.pull_requests[0].head.sha;
  } else if (githubEvent === 'check_run' && webHook.action === 'rerequested') {
    //TODO: only check single file in check_run
    pullRequestNumber = webHook.check_run.check_suite.pull_requests[0].number;
    headSha = webHook.check_run.check_suite.pull_requests[0].head.sha;
  } else {
    return callback(null, createResponse(202, 'No action to take'));
  }

  const installationId = webHook.installation.id;
  const owner = webHook.repository.owner.login;
  const repo = webHook.repository.name;

  try {
    const github = await gitHubAuthenticate(process.env.APP_ID, await privateKey, installationId);
    const languageFiles = await getLanguageFiles(github, owner, repo, headSha, pullRequestNumber);
    const checks = await updateCheck(github, owner, repo, headSha, languageFiles);
    if (Array.isArray(checks)) {
      return callback(null, createResponse(200, `Checked ${checks.length} files`));
    } else {
      return callback(null, createResponse(202, 'No translations found to check'));
    }
  } catch (e) {
    return callback(e);
  }
}

'use strict';

const GitHubApi = require('@octokit/rest'),
  AWS = require('aws-sdk'),
  jwt = require('jsonwebtoken'),
  crypto = require('crypto');

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

async function checkLanguageFiles(github, owner, repo, headSha, pullRequestNumber) {

  const files = await github.pullRequests.getFiles({
    owner,
    repo,
    number: pullRequestNumber
  });

  console.log(files);

  files.data.forEach(async file => {

    console.log(file);
    //if file path contains locale
    const fileContents = await github.repos.getContent({
      owner: owner,
      repo: repo,
      ref: headSha,
      path: file.filename
    });
    const fileText = Buffer.from(fileContents.data.content, 'base64').toString();
    console.log(fileText);
  });

  return {
    success: true,
    description: 'testing'
  };
}

function updateCheck(github, owner, repo, sha, success, description, lineNumber) {

  let checkParams = {
    owner: owner,
    repo: repo,
    name: 'en.json',
    head_sha: sha,
    status: 'completed',
    conclusion: success ? 'success' : 'failure',
    completed_at: new Date().toISOString(),
    output: {
      title: success ? 'Success' : 'Failure',
      summary: description
    }
  };
  if (!success) {
    checkParams.output.annotations = [{
      path: 'package.json',
      start_line: lineNumber,
      end_line: lineNumber,
      annotation_level: 'failure',
      message: description
    }];
  }

  return github.checks.create(checkParams);
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
    const languageCheck = await checkLanguageFiles(github, owner, repo, headSha, pullRequestNumber);
    const res = await updateCheck(github, owner, repo, headSha, languageCheck.success, languageCheck.description, languageCheck.lineNumber);
    return callback(null, createResponse(200, res.data.output.summary));
  } catch (e) {
    return callback(e);
  }
}

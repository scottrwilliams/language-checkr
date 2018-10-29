'use strict';

const GitHubApi = require('@octokit/rest'),
  AWS = require('aws-sdk'),
  jwt = require('jsonwebtoken'),
  crypto = require('crypto'),
  path = require('path'),
  langValidator = require('messageformat-validator');

const SOURCE_LOCAL = 'en';

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

async function getSourceDir(github, owner, repo, headSha) {
  const files = await github.repos.getContent({
    owner,
    repo,
    ref: headSha,
    path: ''
  });
  const sergeFile = files.data.filter(file =>
    file.type === 'file' &&
    file.path.endsWith('.serge.json')
  );
  let sourceDir;
  if (sergeFile.length === 1) {
    const sergeContents = await github.repos.getContent({
      owner,
      repo,
      ref: headSha,
      path: sergeFile[0].path
    })
    sourceDir = JSON.parse(Buffer.from(sergeContents.data.content, 'base64')).source_dir;
  }
  return sourceDir;
}

async function getLanguageFiles(github, owner, repo, headSha, sourceDir, pullRequestNumber, checkRunName) {
  if (!sourceDir) {
    return;
  }

  let languageFiles;
  if (checkRunName) {
    //only check single file in a check_run
    languageFiles = [{
      filename: path.join(sourceDir, checkRunName)
    }];
  } else {
    let allFiles;
    if (pullRequestNumber) {
      const getFiles = await github.pullRequests.getFiles({
        owner,
        repo,
        number: pullRequestNumber,
        per_page: 100
      });
      allFiles = getFiles.data;
    } else {
      const getCommit = await github.repos.getCommit({
        owner,
        repo,
        sha: headSha
      });
      allFiles = getCommit.data.files;
    }
    languageFiles = allFiles.filter(file =>
      file.status !== 'removed' &&
      file.filename.startsWith(sourceDir) &&
      file.filename.endsWith('.json')
    );
  }

  //grab local source file if it isn't part of the pull request
  if (languageFiles.length > 0 &&
    !languageFiles.some(file => path.basename(file.filename, '.json') === SOURCE_LOCAL)) {
    languageFiles.push({
      filename: path.join(sourceDir, SOURCE_LOCAL + '.json'),
      autoAddedSource: true
    });
  }

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
      fileText: Buffer.from(fileContents.data.content, 'base64').toString(),
      autoAddedSource: !!file.autoAddedSource
    };
  }));
}

async function updateCheck(github, owner, repo, headSha, sourceDir, languageFiles) {

  if (!sourceDir || languageFiles.length === 0) {
    let title, summary, conclusion;
    if (!sourceDir) {
      title = 'Did not find the necessary config file';
      summary = 'Could not find a .serge.json file that defines the `source_dir` folder where translations are stored';
      conclusion = 'cancelled';
    } else {
      title = 'Did not find any translations';
      summary = `No translation files found as part of the commit within the directory \`${sourceDir}\``;
      conclusion = 'neutral';
    }
    return github.checks.create({
      owner,
      repo,
      name: 'Language Checker',
      head_sha: headSha,
      status: 'completed',
      conclusion,
      completed_at: new Date().toISOString(),
      output: {
        title,
        summary
      }
    });
  }

  const fileLookup = new Map();
  languageFiles.forEach(file => {
    fileLookup.set(file.fileName, {
      filePath: file.filePath,
      autoAddedSource: file.autoAddedSource
    });
  });

  const input = {
    locales: languageFiles.reduce(
      (obj, file) => {
        obj[file.fileName] = file.fileText;
        return obj;
      }, {}
    ),
    sourceLocale: SOURCE_LOCAL
  };

  const output = langValidator.validateLocales(input);
  let allChecksPassed = true;

  const allFileChecks = await Promise.all(output.map(locale => {

    if (!locale.parsed) {
      allChecksPassed = false;
      let summary = `There was an error while parsing the file: \`${locale._error.message}\``;
      if (locale.locale === SOURCE_LOCAL) {
        summary += '\n\n**NOTE: Since this is the source translation file, no other translations could be processed for errors.**';
      }
      return github.checks.create({
        owner,
        repo,
        name: `File: ${locale.locale}.json`,
        head_sha: headSha,
        status: 'completed',
        conclusion: 'failure',
        completed_at: new Date().toISOString(),
        output: {
          title: 'The translation file is not valid',
          summary
        }
      });
    }

    //don't add check for source file if it was auto-added
    if (fileLookup.get(locale.locale).autoAddedSource) {
      return;
    }

    const errors = locale.report.totals.errors;
    const warnings = locale.report.totals.warnings;

    if (errors === 0 && warnings === 0) {
      return github.checks.create({
        owner,
        repo,
        name: `File: ${locale.locale}.json`,
        head_sha: headSha,
        status: 'completed',
        conclusion: 'success',
        completed_at: new Date().toISOString(),
        output: {
          title: 'No issues with translations',
          summary: 'Yay!'
        }
      });
    }

    //cap issues at 100 so raw output isn't larger than GitHub size limit for summary
    let limitOutput = false;
    if (locale.issues.length > 100) {
      locale.issues.length = 100;
      limitOutput = true;
    }

    const rawOutput = locale.issues.reduce(
      (output, issue) => output +
      `${issue.type} ${issue.level}\n` +
      `  Message: ${issue.msg}\n` +
      `  File: ${issue.locale}.json\n` +
      `  Line: ${issue.line}:${issue.column}\n` +
      `  Key: ${issue.key}\n` +
      `  Target: ${issue.target}\n` +
      `  Source: ${issue.source}\n\n`, ""
    );

    let summary = '**There are issues with the translations!**\n\n```\n' +
      JSON.stringify(locale.report, null, 2) +
      '\n```\n<details><summary>Show Raw Output</summary>\n\n```\n' +
      rawOutput +
      '```\n</details>';

    //cap annotations at 50 for GitHub limits
    if (locale.issues.length > 50) {
      locale.issues.length = 50;
      summary += '<br>\n\n';
      if (limitOutput) {
        summary += '**NOTE: Only showing the first 100 issues in output above**\n';
      }
      summary += '**NOTE: Only showing the first 50 annotations below**';
    }

    if (errors > 0) {
      allChecksPassed = false;
    }

    return github.checks.create({
      owner,
      repo,
      name: `File: ${locale.locale}.json`,
      head_sha: headSha,
      status: 'completed',
      conclusion: errors === 0 ? 'neutral' : 'failure',
      completed_at: new Date().toISOString(),
      output: {
        title: `Found ${errors} error(s), ${warnings} warning(s)`,
        summary: summary,
        annotations: locale.issues.map(issue => ({
          path: fileLookup.get(locale.locale).filePath,
          start_line: issue.line,
          end_line: issue.line,
          annotation_level: issue.level === 'error' ? 'failure' : issue.level,
          title: `${issue.type} ${issue.level}`,
          message: issue.msg,
          raw_details: `Key: ${issue.key}\nSource: ${issue.source}`
        }))
      }
    });
  }));

  await github.checks.create({
    owner,
    repo,
    name: 'Language Checker',
    head_sha: headSha,
    status: 'completed',
    conclusion: allChecksPassed ? 'success' : 'failure',
    completed_at: new Date().toISOString(),
    output: {
      title: allChecksPassed ? 'No errors with the translation files' : 'Found at least 1 problem with a translation file',
      summary: allChecksPassed ? 'Yay!' : 'Please see individual checks for more details'
    }
  });

  return allFileChecks;
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
  if (!((githubEvent === 'check_suite' && (webHook.action === 'requested' || webHook.action === 'rerequested')) ||
      (githubEvent === 'check_run' && webHook.action === 'rerequested') ||
      (githubEvent === 'pull_request' && (webHook.action === 'opened' || webHook.action === 'reopened')))) {
    return callback(null, createResponse(202, 'No action to take'));
  }

  const installationId = webHook.installation.id;
  const owner = webHook.repository.owner.login;
  const repo = webHook.repository.name;
  let github;
  try {
    github = await gitHubAuthenticate(process.env.APP_ID, await privateKey, installationId);
  } catch (e) {
    return callback(e);
  }

  let headSha, pullRequestNumber, checkRunName;
  if (githubEvent === 'check_suite') {
    headSha = webHook.check_suite.head_sha;
    if (webHook.check_suite.pull_requests.length > 0 &&
      webHook.check_suite.pull_requests[0].head.sha === headSha) {
      //need to list all files in PR if latest commit is part of an open PR
      pullRequestNumber = webHook.check_suite.pull_requests[0].number;
    }
  } else if (githubEvent === 'check_run') {
    headSha = webHook.check_run.head_sha;
    if (webHook.check_run.name === 'Language Checker') {
      //if check run gets re-run not on a specific language file, run all checks again
      if (webHook.check_run.check_suite.pull_requests.length > 0 &&
        webHook.check_run.check_suite.pull_requests[0].head.sha === headSha) {
        pullRequestNumber = webHook.check_run.check_suite.pull_requests[0].number;
      }
    } else {
      checkRunName = webHook.check_run.name.replace('File: ', '');
    }
  } else if (githubEvent === 'pull_request') {
    //update checks to include all files in new PR
    headSha = webHook.pull_request.head.sha;
    pullRequestNumber = webHook.pull_request.number;
    //check if commit was flagged with "skip-checks: true"
    const checks = await github.checks.listSuitesForRef({
      owner,
      repo,
      ref: headSha,
      app_id: process.env.APP_ID
    });
    if (!checks.data.total_count) {
      return callback(null, createResponse(202, 'Checks have been flagged to skip'));
    }
  }

  try {
    const sourceDir = await getSourceDir(github, owner, repo, headSha);
    const languageFiles = await getLanguageFiles(github, owner, repo, headSha, sourceDir, pullRequestNumber, checkRunName);
    const checks = await updateCheck(github, owner, repo, headSha, sourceDir, languageFiles);
    if (Array.isArray(checks)) {
      return callback(null, createResponse(200, `Checked ${checks.length} files`));
    } else {
      return callback(null, createResponse(202, 'No translations found to check'));
    }
  } catch (e) {
    return callback(e);
  }
}

# Mirror Repository Sync Setup

This document explains how to configure the automatic synchronization of release artifacts to a mirror repository.

## Overview

After a release is successfully created in the main repository, the workflow can automatically upload the same release artifacts (*.tar.gz files and checksums) to another repository in a different organization.

## Configuration Steps

### 1. Create a Personal Access Token (PAT)

You need to create a GitHub Personal Access Token with appropriate permissions:

1. Go to GitHub Settings → Developer settings → Personal access tokens → Tokens (classic)
2. Click "Generate new token (classic)"
3. Give it a descriptive name (e.g., "ecapture_decryptor mirror sync")
4. Select the following scopes:
   - `repo` (Full control of private repositories)
5. Click "Generate token"
6. **Copy the token immediately** (you won't see it again!)

### 2. Add the Token as a Secret

In your **main repository** (where the workflow runs):

1. Go to Settings → Secrets and variables → Actions
2. Click "New repository secret"
3. Name: `MIRROR_REPO_TOKEN`
4. Value: Paste the PAT you created
5. Click "Add secret"

### 3. Configure the Mirror Repository Variable

In your **main repository**:

1. Go to Settings → Secrets and variables → Actions → Variables tab
2. Click "New repository variable"
3. Name: `MIRROR_REPO`
4. Value: The target repository in format `owner/repo` (e.g., `another-org/ecapture_decryptor_mirror`)
5. Click "Add variable"

### 4. Prepare the Mirror Repository

In your **mirror repository** (target):

1. Create the repository if it doesn't exist
2. Make sure the PAT owner has write access to this repository
3. The repository can be empty - releases will be created automatically

## How It Works

When you push a tag (e.g., `v1.0.0`):

1. **build-release** job: Builds artifacts for all platforms
2. **create-release** job: Creates release in the main repository
3. **sync-to-mirror** job: Automatically syncs artifacts to the mirror repository
   - Only runs if `MIRROR_REPO` variable is set
   - Downloads all build artifacts
   - Creates/updates release in the mirror repository
   - Uploads all *.tar.gz files and checksums

## Testing

To test the setup:

1. Ensure all secrets and variables are configured
2. Push a test tag: `git tag v0.0.1-test && git push origin v0.0.1-test`
3. Check the Actions tab to see the workflow progress
4. Verify the release appears in both repositories

## Disabling Mirror Sync

To disable syncing without removing the configuration:

1. Go to repository Settings → Secrets and variables → Actions → Variables
2. Delete or rename the `MIRROR_REPO` variable
3. The sync job will be skipped automatically

## Troubleshooting

### Sync job fails with authentication error

- Verify the `MIRROR_REPO_TOKEN` secret is set correctly
- Check that the PAT hasn't expired
- Ensure the PAT has `repo` scope

### Sync job is skipped

- Check that `MIRROR_REPO` variable is set
- Verify the variable value is in correct format: `owner/repo`

### Release created but no assets uploaded

- Check the workflow logs for the "Download all artifacts" step
- Verify that build artifacts were created successfully
- Ensure the file pattern `dist/**/*.tar.gz*` matches your artifacts

## Security Considerations

- The PAT should only be granted access to the specific mirror repository
- Use repository-specific tokens when possible
- Rotate tokens periodically
- Never commit tokens to the repository
- Consider using GitHub App tokens for enhanced security

## Example Configuration

**Repository Variables:**
```
MIRROR_REPO = "example-org/ecapture_decryptor_releases"
```

**Repository Secrets:**
```
MIRROR_REPO_TOKEN = ghp_xxxxxxxxxxxxxxxxxxxx
```

With this configuration, when you release `v1.2.3`:
- Main repo: `https://github.com/cfc4n/ecapture_decryptor/releases/tag/v1.2.3`
- Mirror repo: `https://github.com/example-org/ecapture_decryptor_releases/releases/tag/v1.2.3`


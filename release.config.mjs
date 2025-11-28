/**
 * Semantic Release Configuration for Open Sesame
 *
 * Automates versioning and release based on conventional commits.
 * Updates Cargo.toml version, generates CHANGELOG.md, creates GitHub releases.
 *
 * @type {import('semantic-release').GlobalConfig}
 */
export default {
  branches: ['main'],
  plugins: [
    // Analyze commits to determine version bump
    [
      '@semantic-release/commit-analyzer',
      {
        preset: 'conventionalcommits',
        releaseRules: [
          { type: 'feat', release: 'minor' },
          { type: 'fix', release: 'patch' },
          { type: 'perf', release: 'patch' },
          { type: 'revert', release: 'patch' },
          { type: 'docs', scope: 'README', release: 'patch' },
          { type: 'style', release: false },
          { type: 'chore', release: false },
          { type: 'refactor', release: false },
          { type: 'test', release: false },
          { type: 'build', release: false },
          { type: 'ci', release: false },
          { scope: 'no-release', release: false },
        ],
      },
    ],

    // Generate release notes from commits
    [
      '@semantic-release/release-notes-generator',
      {
        preset: 'conventionalcommits',
        presetConfig: {
          types: [
            { type: 'feat', section: '✨ Features' },
            { type: 'fix', section: '🐛 Bug Fixes' },
            { type: 'perf', section: '⚡ Performance Improvements' },
            { type: 'revert', section: '⏪ Reverts' },
            { type: 'docs', section: '📚 Documentation' },
            { type: 'style', section: '💄 Styles', hidden: true },
            { type: 'chore', section: '🔧 Chores', hidden: true },
            { type: 'refactor', section: '♻️ Code Refactoring' },
            { type: 'test', section: '✅ Tests', hidden: true },
            { type: 'build', section: '📦 Build System' },
            { type: 'ci', section: '👷 CI/CD' },
          ],
        },
      },
    ],

    // Update CHANGELOG.md
    [
      '@semantic-release/changelog',
      {
        changelogFile: 'CHANGELOG.md',
      },
    ],

    // Update Cargo.toml version (Rust-specific)
    [
      '@semantic-release/exec',
      {
        prepareCmd:
          "sed -i 's/^version = \".*\"/version = \"${nextRelease.version}\"/' Cargo.toml",
      },
    ],

    // Commit the changed files
    [
      '@semantic-release/git',
      {
        assets: ['CHANGELOG.md', 'Cargo.toml', 'Cargo.lock'],
        message:
          'chore(release): ${nextRelease.version} [skip ci]\n\n${nextRelease.notes}',
      },
    ],

    // Create GitHub release
    '@semantic-release/github',
  ],
};

// Commitlint configuration for conventional commits
// https://commitlint.js.org/
const config = {
  extends: ['@commitlint/config-conventional'],
  rules: {
    // Commit types aligned with semantic-release
    'type-enum': [
      2,
      'always',
      [
        'feat',     // New feature (minor release)
        'fix',      // Bug fix (patch release)
        'perf',     // Performance improvement (patch release)
        'revert',   // Revert previous commit (patch release)
        'docs',     // Documentation only
        'style',    // Code style (formatting, no logic change)
        'refactor', // Code refactoring (no feature/fix)
        'test',     // Adding/updating tests
        'build',    // Build system or dependencies
        'ci',       // CI/CD configuration
        'chore',    // Maintenance tasks
      ],
    ],
    // Enforce lowercase subject
    'subject-case': [2, 'always', 'lower-case'],
    // Ensure subject is not empty
    'subject-empty': [2, 'never'],
    // Ensure type is not empty
    'type-empty': [2, 'never'],
    // Max header length
    'header-max-length': [2, 'always', 100],
  },
};

module.exports = config;

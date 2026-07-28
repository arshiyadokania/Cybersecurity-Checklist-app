'use strict';

/*
 * DETECTION FIXTURE — NOT REAL CREDENTIALS, NOT APPLICATION CODE.
 *
 * This file exists ONLY so the secret scanner (gitleaks) has something to
 * catch, proving detection is wired up. The values below are AWS's own public
 * DOCUMENTATION EXAMPLE credentials — they are not valid and grant access to
 * nothing. gitleaks' aws-access-token rule (AKIA + 16 chars) still flags them,
 * while platform push-protection allowlists these well-known example values.
 *
 * This file must NEVER be imported by application code.
 */

// gitleaks aws-access-token rule: AKIA + 16 uppercase alphanumerics.
const AWS_ACCESS_KEY_ID = 'AKIAIOSF••••••••••••';
const AWS_SECRET_ACCESS_KEY = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY';

module.exports = { AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY };
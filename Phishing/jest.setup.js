'use strict';

// Extends expect with DOM matchers (toBeInTheDocument, toHaveFocus, ...).
require('@testing-library/jest-dom');

// jsdom does not provide TextEncoder/TextDecoder, which some libraries expect.
const { TextEncoder, TextDecoder } = require('util');
if (typeof global.TextEncoder === 'undefined') {
  global.TextEncoder = TextEncoder;
}
if (typeof global.TextDecoder === 'undefined') {
  global.TextDecoder = TextDecoder;
}